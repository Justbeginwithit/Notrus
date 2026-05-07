import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

function isoNow() {
  return new Date().toISOString();
}

function randomB64(bytes = 32) {
  return randomBytes(bytes).toString("base64");
}

function randomJwk() {
  return {
    crv: "P-256",
    kty: "EC",
    x: randomB64(32),
    y: randomB64(32),
  };
}

function identityPayload({ userId, username, displayName }) {
  return {
    createdAt: isoNow(),
    displayName,
    encryptionPublicJwk: randomJwk(),
    fingerprint: randomBytes(16).toString("hex"),
    prekeyCreatedAt: isoNow(),
    prekeyFingerprint: randomBytes(16).toString("hex"),
    prekeyPublicJwk: randomJwk(),
    prekeySignature: randomB64(64),
    recoveryFingerprint: randomBytes(16).toString("hex"),
    recoveryPublicJwk: randomJwk(),
    signingPublicJwk: randomJwk(),
    userId,
    username,
  };
}

function leadingZeroBits(bytes) {
  let count = 0;
  for (const value of bytes) {
    if (value === 0) {
      count += 8;
      continue;
    }
    for (let bit = 7; bit >= 0; bit -= 1) {
      if ((value & (1 << bit)) === 0) {
        count += 1;
      } else {
        return count;
      }
    }
  }
  return count;
}

function solvePowChallenge(challenge) {
  const difficultyBits = Number(challenge?.difficultyBits ?? 0);
  const token = typeof challenge?.token === "string" ? challenge.token : "";
  if (!token) {
    throw new Error("Relay returned an invalid proof-of-work challenge token.");
  }

  for (let counter = 0; counter < 60_000_000; counter += 1) {
    const nonce = counter.toString(16);
    const digest = createHash("sha256").update(`${token}:${nonce}`).digest();
    if (leadingZeroBits(digest) >= difficultyBits) {
      return nonce;
    }
  }
  throw new Error("Unable to solve proof-of-work challenge.");
}

async function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
  });
}

function request(origin, pathname, { method = "GET", body = null, headers = {} } = {}) {
  const url = new URL(pathname, origin);
  const payload = body == null ? null : Buffer.from(JSON.stringify(body), "utf8");
  return new Promise((resolve, reject) => {
    const req = http.request(
      url,
      {
        method,
        headers: payload
          ? {
              "Content-Length": String(payload.length),
              "Content-Type": "application/json",
              ...headers,
            }
          : headers,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let decoded = {};
          try {
            decoded = raw ? JSON.parse(raw) : {};
          } catch {
            decoded = { raw };
          }
          resolve({
            body: decoded,
            statusCode: response.statusCode ?? 0,
          });
        });
      }
    );
    req.on("error", reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

async function requestWithPow(origin, pathname, options = {}) {
  const initial = await request(origin, pathname, options);
  if (initial.statusCode !== 428 || !initial.body?.powChallenge) {
    return initial;
  }

  const challenge = initial.body.powChallenge;
  const nonce = solvePowChallenge(challenge);
  const retryHeaders = {
    ...(options.headers ?? {}),
    [challenge.tokenField ?? "X-Notrus-Pow-Token"]: challenge.token,
    [challenge.nonceField ?? "X-Notrus-Pow-Nonce"]: nonce,
  };
  return request(origin, pathname, {
    ...options,
    headers: retryHeaders,
  });
}

async function waitForHealth(origin) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const health = await request(origin, "/api/health");
      if (health.statusCode === 200) {
        return health.body;
      }
    } catch {
      // keep waiting
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for relay health at ${origin}.`);
}

async function main() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "notrus-production-api-boundary-"));
  const port = await reservePort();
  const origin = `http://127.0.0.1:${port}`;
  const suffix = randomBytes(3).toString("hex");
  const alice = identityPayload({
    displayName: "Prod Boundary Alice",
    userId: `prod-boundary-alice-${suffix}`,
    username: `prodalice${suffix}`,
  });
  const bob = identityPayload({
    displayName: "Prod Boundary Bob",
    userId: `prod-boundary-bob-${suffix}`,
    username: `prodbob${suffix}`,
  });

  const relay = spawn(process.execPath, ["server.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      NODE_ENV: "production",
      NOTRUS_DATA_DIR: path.join(tempDir, "relay-data"),
      NOTRUS_PROTOCOL_POLICY: "require-standards",
      PORT: String(port),
    },
    stdio: "ignore",
  });

  try {
    const health = await waitForHealth(origin);
    if (health?.privacy?.legacyRoutesEnabled !== false) {
      throw new Error("Production relay should expose legacyRoutesEnabled=false in /api/health.");
    }

    const aliceRegistration = await requestWithPow(origin, "/api/bootstrap/register", {
      body: alice,
      method: "POST",
    });
    if (aliceRegistration.statusCode !== 200) {
      throw new Error(`Alice registration failed with HTTP ${aliceRegistration.statusCode}.`);
    }

    const bobRegistration = await requestWithPow(origin, "/api/bootstrap/register", {
      body: bob,
      method: "POST",
    });
    if (bobRegistration.statusCode !== 200) {
      throw new Error(`Bob registration failed with HTTP ${bobRegistration.statusCode}.`);
    }

    const legacySync = await request(origin, `/api/sync?userId=${encodeURIComponent(alice.userId)}`);
    if (legacySync.statusCode !== 410) {
      throw new Error(`Legacy /api/sync must be disabled in production, got HTTP ${legacySync.statusCode}.`);
    }

    const legacyThread = await request(origin, "/api/threads", {
      method: "POST",
      body: {
        createdAt: isoNow(),
        id: `legacy-thread-${suffix}`,
        participantIds: [alice.userId, bob.userId],
        protocol: "signal-pqxdh-double-ratchet-v1",
        title: "legacy",
      },
    });
    if (legacyThread.statusCode !== 410) {
      throw new Error(`Legacy /api/threads must be disabled in production, got HTTP ${legacyThread.statusCode}.`);
    }

    const legacyEvents = await request(origin, "/events");
    if (legacyEvents.statusCode !== 410) {
      throw new Error(`Legacy /events must be disabled in production, got HTTP ${legacyEvents.statusCode}.`);
    }

    const sessionToken = aliceRegistration.body?.session?.token;
    if (!sessionToken) {
      throw new Error("Relay did not return a bootstrap session token for routing API verification.");
    }

    const legacyMessagePost = await request(origin, "/api/threads/legacy/messages", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
      body: {
        createdAt: isoNow(),
        id: `legacy-message-${suffix}`,
        messageKind: "signal-prekey",
        protocol: "signal-pqxdh-double-ratchet-v1",
        wireMessage: randomB64(48),
      },
    });
    if (legacyMessagePost.statusCode !== 410) {
      throw new Error(`Legacy message post must be disabled in production, got HTTP ${legacyMessagePost.statusCode}.`);
    }

    const search = await request(origin, `/api/directory/search?q=${encodeURIComponent(bob.username)}`, {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
      method: "GET",
    });
    if (search.statusCode !== 200) {
      throw new Error(`Directory search failed with HTTP ${search.statusCode}.`);
    }

    const bobHandle = search.body?.results?.find?.((entry) => entry?.id === bob.userId)?.contactHandle;
    if (!bobHandle) {
      throw new Error("Opaque contact handle search did not return a contact handle for Bob.");
    }

    const thread = await request(origin, "/api/routing/threads", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
      body: {
        createdAt: isoNow(),
        id: `routing-thread-${suffix}`,
        participantHandles: [bobHandle],
        protocol: "signal-pqxdh-double-ratchet-v1",
        title: "direct",
      },
    });
    if (thread.statusCode !== 201) {
      throw new Error(`Opaque routing thread creation failed with HTTP ${thread.statusCode}.`);
    }

    const aliceInitialSync = await request(origin, "/api/sync/state", {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
      method: "GET",
    });
    if (aliceInitialSync.statusCode !== 200) {
      throw new Error(`Initial opaque sync failed with HTTP ${aliceInitialSync.statusCode}.`);
    }
    const createdThread = aliceInitialSync.body?.threads?.find?.((entry) => entry?.id === thread.body?.threadId);
    if (!createdThread?.mailboxHandle || !createdThread?.deliveryCapability) {
      throw new Error("Opaque sync did not return mailbox routing material for the created thread.");
    }

    const deliveredMessageId = `delivery-message-${suffix}`;
    const messagePost = await request(origin, `/api/mailboxes/${encodeURIComponent(createdThread.mailboxHandle)}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${createdThread.deliveryCapability}`,
      },
      body: {
        createdAt: isoNow(),
        id: deliveredMessageId,
        messageKind: "signal-prekey",
        protocol: "signal-pqxdh-double-ratchet-v1",
        wireMessage: randomB64(64),
      },
    });
    if (messagePost.statusCode !== 201) {
      throw new Error(`Opaque mailbox message post failed with HTTP ${messagePost.statusCode}.`);
    }

    const bobSessionToken = bobRegistration.body?.session?.token;
    if (!bobSessionToken) {
      throw new Error("Relay did not return a bootstrap session token for Bob.");
    }
    const bobSync = await request(origin, "/api/sync/state", {
      headers: {
        Authorization: `Bearer ${bobSessionToken}`,
      },
      method: "GET",
    });
    if (bobSync.statusCode !== 200) {
      throw new Error(`Bob opaque sync failed with HTTP ${bobSync.statusCode}.`);
    }
    const bobThread = bobSync.body?.threads?.find?.((entry) => entry?.id === thread.body?.threadId);
    if (!bobThread?.mailboxHandle || !bobThread?.deliveryCapability) {
      throw new Error("Bob sync did not return mailbox routing material for the created thread.");
    }

    const forgedEdit = await request(
      origin,
      `/api/mailboxes/${encodeURIComponent(bobThread.mailboxHandle)}/messages/${encodeURIComponent(deliveredMessageId)}/edit`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${bobThread.deliveryCapability}`,
        },
        body: {
          createdAt: isoNow(),
          id: `forged-edit-${suffix}`,
          messageKind: "signal-prekey",
          protocol: "signal-pqxdh-double-ratchet-v1",
          wireMessage: randomB64(64),
        },
      }
    );
    if (forgedEdit.statusCode !== 403) {
      throw new Error(`Recipient must not be able to edit sender messages, got HTTP ${forgedEdit.statusCode}.`);
    }

    const forgedDelete = await request(
      origin,
      `/api/mailboxes/${encodeURIComponent(bobThread.mailboxHandle)}/messages/${encodeURIComponent(deliveredMessageId)}/delete`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${bobThread.deliveryCapability}`,
        },
        body: {
          deletedAt: isoNow(),
        },
      }
    );
    if (forgedDelete.statusCode !== 403) {
      throw new Error(`Recipient must not be able to delete sender messages for everyone, got HTTP ${forgedDelete.statusCode}.`);
    }

    const editMessageId = `edit-message-${suffix}`;
    const editPost = await request(
      origin,
      `/api/mailboxes/${encodeURIComponent(createdThread.mailboxHandle)}/messages/${encodeURIComponent(deliveredMessageId)}/edit`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${createdThread.deliveryCapability}`,
        },
        body: {
          createdAt: isoNow(),
          id: editMessageId,
          messageKind: "signal-whisper",
          protocol: "signal-pqxdh-double-ratchet-v1",
          wireMessage: randomB64(64),
        },
      }
    );
    if (editPost.statusCode !== 201) {
      throw new Error(`Sender message edit failed with HTTP ${editPost.statusCode}.`);
    }

    const deletePost = await request(
      origin,
      `/api/mailboxes/${encodeURIComponent(createdThread.mailboxHandle)}/messages/${encodeURIComponent(deliveredMessageId)}/delete`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${createdThread.deliveryCapability}`,
        },
        body: {
          deletedAt: isoNow(),
        },
      }
    );
    if (deletePost.statusCode !== 200) {
      throw new Error(`Sender delete-for-everyone failed with HTTP ${deletePost.statusCode}.`);
    }

    const aliceReceiptSync = await request(origin, "/api/sync/state", {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
      method: "GET",
    });
    const deliveryReceipt = aliceReceiptSync.body?.threads
      ?.find?.((entry) => entry?.id === thread.body?.threadId)
      ?.deliveryReceipts
      ?.find?.((receipt) => receipt?.userId === bob.userId);
    if (deliveryReceipt?.lastDeliveredMessageId !== deliveredMessageId) {
      throw new Error("Recipient sync did not create a durable delivery receipt visible to the sender.");
    }
    const editedThread = aliceReceiptSync.body?.threads?.find?.((entry) => entry?.id === thread.body?.threadId);
    const originalAfterDelete = editedThread?.messages?.find?.((message) => message?.id === deliveredMessageId);
    const editEvent = editedThread?.messages?.find?.((message) => message?.id === editMessageId);
    if (originalAfterDelete?.deletedForEveryoneAt == null || originalAfterDelete?.wireMessage !== null) {
      throw new Error("Delete-for-everyone did not tombstone the original message and remove its relay ciphertext.");
    }
    if (editEvent?.editOf !== deliveredMessageId) {
      throw new Error("Authenticated message edit event did not sync with its target editOf reference.");
    }

    const syncState = await request(origin, "/api/sync/state", {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
      method: "GET",
    });
    if (syncState.statusCode !== 200) {
      throw new Error(`Opaque sync endpoint failed with HTTP ${syncState.statusCode}.`);
    }

    console.log("production-api-boundary: production relay disabled legacy /api/sync and /api/threads while keeping opaque routing APIs operational");
  } finally {
    if (!relay.killed) {
      relay.kill("SIGTERM");
    }
    await new Promise((resolve) => relay.once("exit", resolve));
    await rm(tempDir, { force: true, recursive: true }).catch(() => {});
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
