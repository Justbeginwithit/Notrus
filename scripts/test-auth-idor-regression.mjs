import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { withManagedRelay } from "./managed-relay.mjs";

function isoNow() {
  return new Date().toISOString();
}

function randomBase64(bytes = 32) {
  return randomBytes(bytes).toString("base64");
}

function generateEcKeyMaterial() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  return {
    privateKey,
    publicJwk: {
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    },
  };
}

function signalBundle() {
  const bytes = () => randomBase64(32);
  return {
    deviceId: 1,
    identityKey: bytes(),
    kyberPreKeyId: 1,
    kyberPreKeyPublic: bytes(),
    kyberPreKeySignature: bytes(),
    preKeyId: 1,
    preKeyPublic: bytes(),
    registrationId: 1001,
    signedPreKeyId: 1,
    signedPreKeyPublic: bytes(),
    signedPreKeySignature: bytes(),
  };
}

function identity(username) {
  const signing = generateEcKeyMaterial();
  const encryption = generateEcKeyMaterial();
  const recovery = generateEcKeyMaterial();
  const prekey = generateEcKeyMaterial();
  return {
    keys: { encryption, prekey, recovery, signing },
    payload: {
      createdAt: isoNow(),
      displayName: username,
      encryptionPublicJwk: encryption.publicJwk,
      fingerprint: randomBytes(16).toString("hex"),
      prekeyCreatedAt: isoNow(),
      prekeyFingerprint: randomBytes(16).toString("hex"),
      prekeyPublicJwk: prekey.publicJwk,
      prekeySignature: randomBase64(64),
      recoveryFingerprint: randomBytes(16).toString("hex"),
      recoveryPublicJwk: recovery.publicJwk,
      signalBundle: signalBundle(),
      signingPublicJwk: signing.publicJwk,
      userId: `user-${randomBytes(8).toString("hex")}`,
      username,
    },
  };
}

function device(label) {
  const signing = generateEcKeyMaterial();
  return {
    descriptor: {
      createdAt: isoNow(),
      id: `device-${randomBytes(6).toString("hex")}`,
      label,
      platform: "test",
      publicJwk: signing.publicJwk,
      riskLevel: "low",
      storageMode: "test-device-key",
    },
    privateKey: signing.privateKey,
  };
}

function signDevicePayload(privateKey, payload) {
  const signer = createSign("sha256");
  signer.update(payload);
  signer.end();
  return signer.sign(privateKey).toString("base64");
}

async function request(origin, pathname, { body = null, headers = {}, method = "GET", token = null } = {}) {
  const response = await fetch(new URL(pathname, origin), {
    method,
    headers: {
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const raw = await response.text();
  let decoded = {};
  try {
    decoded = raw ? JSON.parse(raw) : {};
  } catch {
    decoded = { raw };
  }
  return { body: decoded, statusCode: response.status };
}

function expectStatus(label, response, allowedStatuses) {
  if (!allowedStatuses.includes(response.statusCode)) {
    throw new Error(`${label} returned HTTP ${response.statusCode}, expected ${allowedStatuses.join(" or ")}.`);
  }
}

function expectDenied(label, response) {
  expectStatus(label, response, [401, 403, 410]);
}

async function openSse(origin, pathname, token) {
  const url = new URL(pathname, origin);
  const client = url.protocol === "https:" ? https : http;
  const events = [];
  const waiters = [];
  let currentEvent = "message";
  let dataLines = [];
  let buffer = "";

  function dispatch(event) {
    events.push(event);
    for (const waiter of [...waiters]) {
      if (waiter.predicate(event)) {
        waiters.splice(waiters.indexOf(waiter), 1);
        clearTimeout(waiter.timer);
        waiter.resolve(event);
      }
    }
  }

  function parseLine(line) {
    if (line.trim() === "") {
      if (dataLines.length > 0) {
        let payload = dataLines.join("\n");
        try {
          payload = JSON.parse(payload);
        } catch {
          payload = { raw: payload };
        }
        dispatch({ event: currentEvent || "message", payload });
      }
      currentEvent = "message";
      dataLines = [];
      return;
    }
    if (line.startsWith("event:")) {
      currentEvent = line.slice("event:".length).trim();
      return;
    }
    if (line.startsWith("data:")) {
      dataLines.push(line.slice("data:".length).trimStart());
    }
  }

  return new Promise((resolve, reject) => {
    const req = client.request(
      url,
      {
        headers: {
          Accept: "text/event-stream",
          Authorization: `Bearer ${token}`,
          "Cache-Control": "no-store",
        },
        method: "GET",
      },
      (response) => {
        if ((response.statusCode ?? 0) < 200 || (response.statusCode ?? 0) >= 300) {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () => reject(new Error(`SSE returned HTTP ${response.statusCode}: ${Buffer.concat(chunks).toString("utf8")}`)));
          return;
        }

        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          buffer += chunk;
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";
          for (const line of lines) {
            parseLine(line.replace(/\r$/, ""));
          }
        });
        response.on("error", reject);

        resolve({
          close: () => req.destroy(),
          waitForEvent(eventName, timeoutMs = 1_200) {
            const existingIndex = events.findIndex((event) => event.event === eventName);
            if (existingIndex >= 0) {
              return Promise.resolve(events.splice(existingIndex, 1)[0]);
            }
            return new Promise((eventResolve, eventReject) => {
              const waiter = {
                predicate: (event) => event.event === eventName,
                resolve: eventResolve,
                timer: setTimeout(() => {
                  waiters.splice(waiters.indexOf(waiter), 1);
                  eventReject(new Error(`Timed out waiting for SSE event ${eventName}.`));
                }, timeoutMs),
              };
              waiters.push(waiter);
            });
          },
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}

async function expectNoSyncEvent(stream, label) {
  try {
    await stream.waitForEvent("sync", 450);
  } catch {
    return;
  }
  throw new Error(`${label} unexpectedly received a sync event.`);
}

async function register(origin, subject, subjectDevice = null) {
  const response = await request(origin, "/api/bootstrap/register", {
    body: subjectDevice ? { ...subject.payload, device: subjectDevice.descriptor } : subject.payload,
    headers: subjectDevice ? { "X-Notrus-Device-Id": subjectDevice.descriptor.id } : {},
    method: "POST",
  });
  expectStatus(`register ${subject.payload.username}`, response, [200]);
  assert.ok(response.body.session?.token, "Registration must issue a session token.");
  return response.body.session.token;
}

async function contactHandle(origin, token, username) {
  const search = await request(origin, `/api/directory/search?q=${encodeURIComponent(username)}`, { token });
  expectStatus(`search ${username}`, search, [200]);
  const result = search.body.results?.find?.((candidate) => candidate.username === username);
  assert.ok(result?.contactHandle, `Search did not return a contact handle for ${username}.`);
  return result.contactHandle;
}

async function createRoutingThread(origin, token, handle, suffix) {
  const response = await request(origin, "/api/routing/threads", {
    body: {
      createdAt: isoNow(),
      id: `routing-${suffix}-${randomBytes(4).toString("hex")}`,
      participantHandles: [handle],
      protocol: "signal-pqxdh-double-ratchet-v1",
      title: "",
    },
    method: "POST",
    token,
  });
  expectStatus("routing thread create", response, [201]);
  return response.body.threadId;
}

async function runPrimaryRegression({ origin }) {
  const suffix = randomBytes(4).toString("hex");
  const alice = identity(`authalice${suffix}`);
  const bob = identity(`authbob${suffix}`);
  const carol = identity(`authcarol${suffix}`);
  const dave = identity(`authdave${suffix}`);
  const aliceDeviceOne = device("Alice primary");
  const aliceDeviceTwo = device("Alice secondary");

  const aliceSession = await register(origin, alice, aliceDeviceOne);
  const aliceRevokedSession = await register(origin, alice, aliceDeviceTwo);
  const bobSession = await register(origin, bob);
  const carolSession = await register(origin, carol);
  await register(origin, dave);

  expectDenied("unauthenticated legacy sync", await request(origin, `/api/sync?userId=${alice.payload.userId}`));
  expectDenied("cross-user legacy sync", await request(origin, `/api/sync?userId=${bob.payload.userId}`, { token: aliceSession }));
  expectDenied("unauthenticated legacy thread create", await request(origin, "/api/threads", { body: {}, method: "POST" }));
  expectDenied("unauthenticated event stream", await request(origin, "/api/events"));

  const legacyThreadId = `legacy-${suffix}`;
  const createThread = await request(origin, "/api/threads", {
    body: {
      createdAt: isoNow(),
      createdBy: bob.payload.userId,
      id: legacyThreadId,
      participantIds: [alice.payload.userId, bob.payload.userId],
      protocol: "signal-pqxdh-double-ratchet-v1",
      title: "spoofed creator",
    },
    method: "POST",
    token: aliceSession,
  });
  expectStatus("legacy thread create with spoofed createdBy", createThread, [201]);

  const aliceLegacySync = await request(origin, `/api/sync?userId=${alice.payload.userId}`, { token: aliceSession });
  expectStatus("legacy sync after thread create", aliceLegacySync, [200]);
  const legacyThread = aliceLegacySync.body.threads.find((thread) => thread.id === legacyThreadId);
  assert.equal(legacyThread?.createdBy, alice.payload.userId, "Legacy thread creation must force createdBy from the session.");

  const messageId = `msg-${suffix}`;
  const postMessage = await request(origin, `/api/threads/${legacyThreadId}/messages`, {
    body: {
      createdAt: isoNow(),
      id: messageId,
      messageKind: "signal-prekey",
      protocol: "signal-pqxdh-double-ratchet-v1",
      senderId: bob.payload.userId,
      wireMessage: randomBase64(48),
    },
    method: "POST",
    token: aliceSession,
  });
  expectStatus("legacy message post with spoofed senderId", postMessage, [201]);

  const attachmentId = `att-${suffix}`;
  const uploadAttachment = await request(origin, `/api/threads/${legacyThreadId}/attachments`, {
    body: {
      byteLength: 32,
      ciphertext: randomBase64(48),
      createdAt: isoNow(),
      id: attachmentId,
      iv: randomBase64(12),
      senderId: bob.payload.userId,
      sha256: randomBytes(32).toString("hex"),
      threadId: legacyThreadId,
    },
    method: "POST",
    token: aliceSession,
  });
  expectStatus("legacy attachment upload with spoofed senderId", uploadAttachment, [201]);

  const fetchAttachment = await request(origin, `/api/threads/${legacyThreadId}/attachments/${attachmentId}?userId=${alice.payload.userId}`, {
    token: aliceSession,
  });
  expectStatus("legacy attachment fetch", fetchAttachment, [200]);
  assert.equal(fetchAttachment.body.senderId, alice.payload.userId, "Legacy attachment upload must force senderId from the session.");

  const carolFetchSpoof = await request(origin, `/api/threads/${legacyThreadId}/attachments/${attachmentId}?userId=${alice.payload.userId}`, {
    token: carolSession,
  });
  expectDenied("legacy attachment fetch with spoofed userId", carolFetchSpoof);

  const syncAfterMessage = await request(origin, "/api/sync/state", { token: aliceSession });
  expectStatus("privacy sync after message", syncAfterMessage, [200]);
  const syncedThread = syncAfterMessage.body.threads.find((thread) => thread.id === legacyThreadId);
  assert.equal(
    syncedThread?.messages?.find((message) => message.id === messageId)?.senderId,
    alice.payload.userId,
    "Legacy message post must force senderId from the session."
  );

  const mailbox = syncedThread;
  expectDenied(
    "mailbox post without capability",
    await request(origin, `/api/mailboxes/${mailbox.mailboxHandle}/messages`, {
      body: { createdAt: isoNow(), id: `no-cap-${suffix}`, messageKind: "signal-prekey", protocol: "signal-pqxdh-double-ratchet-v1", wireMessage: randomBase64(32) },
      method: "POST",
    })
  );
  expectDenied(
    "mailbox post with wrong handle",
    await request(origin, `/api/mailboxes/wrong-${mailbox.mailboxHandle}/messages`, {
      body: { createdAt: isoNow(), id: `wrong-handle-${suffix}`, messageKind: "signal-prekey", protocol: "signal-pqxdh-double-ratchet-v1", wireMessage: randomBase64(32) },
      method: "POST",
      token: mailbox.deliveryCapability,
    })
  );

  const stream = await openSse(origin, `/api/events?userId=${bob.payload.userId}`, aliceSession);
  await stream.waitForEvent("hello");
  const carolForBob = await contactHandle(origin, bobSession, carol.payload.username);
  await createRoutingThread(origin, bobSession, carolForBob, `bob-carol-${suffix}`);
  await expectNoSyncEvent(stream, "Alice stream bound with Bob query parameter");
  const carolForAlice = await contactHandle(origin, aliceSession, carol.payload.username);
  await createRoutingThread(origin, aliceSession, carolForAlice, `alice-carol-${suffix}`);
  const syncEvent = await stream.waitForEvent("sync");
  stream.close();
  assert.equal(syncEvent.payload.event, "sync-required", "Event stream should use a generic sync-required payload.");
  assert.equal("threadId" in syncEvent.payload, false, "Event payload must not leak thread IDs.");
  assert.equal("reason" in syncEvent.payload, false, "Event payload must not leak detailed reasons.");
  assert.equal("senderId" in syncEvent.payload, false, "Event payload must not leak sender IDs.");
  assert.equal("participantIds" in syncEvent.payload, false, "Event payload must not leak participant lists.");

  const beforeRevokeSync = await request(origin, "/api/sync/state", { token: aliceRevokedSession });
  expectStatus("secondary device sync before revoke", beforeRevokeSync, [200]);
  const secondaryMailbox = beforeRevokeSync.body.threads.find((thread) => thread.id === legacyThreadId);
  assert.ok(secondaryMailbox?.deliveryCapability, "Secondary device should receive a device-bound mailbox capability before revoke.");

  const revokedAt = isoNow();
  const revokePayload = JSON.stringify({
    action: "device-revoke",
    createdAt: revokedAt,
    signerDeviceId: aliceDeviceOne.descriptor.id,
    targetDeviceId: aliceDeviceTwo.descriptor.id,
    userId: alice.payload.userId,
  });
  const revoke = await request(origin, "/api/devices/revoke", {
    body: {
      createdAt: revokedAt,
      signature: signDevicePayload(aliceDeviceOne.privateKey, revokePayload),
      signerDeviceId: aliceDeviceOne.descriptor.id,
      targetDeviceId: aliceDeviceTwo.descriptor.id,
      userId: alice.payload.userId,
    },
    headers: { "X-Notrus-Device-Id": aliceDeviceOne.descriptor.id },
    method: "POST",
  });
  expectStatus("device revoke", revoke, [200]);
  expectDenied("revoked device sync", await request(origin, "/api/sync/state", { token: aliceRevokedSession }));
  expectDenied("revoked device event stream", await request(origin, "/api/events", { token: aliceRevokedSession }));
  expectDenied(
    "revoked device old mailbox capability",
    await request(origin, `/api/mailboxes/${secondaryMailbox.mailboxHandle}/messages`, {
      body: { createdAt: isoNow(), id: `revoked-cap-${suffix}`, messageKind: "signal-prekey", protocol: "signal-pqxdh-double-ratchet-v1", wireMessage: randomBase64(32) },
      method: "POST",
      token: secondaryMailbox.deliveryCapability,
    })
  );
}

async function runExpiryRegression({ origin }) {
  const suffix = randomBytes(4).toString("hex");
  const alice = identity(`expalice${suffix}`);
  const bob = identity(`expbob${suffix}`);
  const aliceSession = await register(origin, alice);
  await register(origin, bob);
  const bobHandle = await contactHandle(origin, aliceSession, bob.payload.username);
  const threadId = await createRoutingThread(origin, aliceSession, bobHandle, `expiry-${suffix}`);
  const sync = await request(origin, "/api/sync/state", { token: aliceSession });
  expectStatus("expiry sync", sync, [200]);
  const thread = sync.body.threads.find((candidate) => candidate.id === threadId);
  assert.ok(thread?.deliveryCapability, "Expiry test did not receive a mailbox capability.");
  await new Promise((resolve) => setTimeout(resolve, 3_200));
  expectDenied("expired session", await request(origin, "/api/sync/state", { token: aliceSession }));
  expectDenied(
    "expired mailbox capability",
    await request(origin, `/api/mailboxes/${thread.mailboxHandle}/messages`, {
      body: { createdAt: isoNow(), id: `expired-${suffix}`, messageKind: "signal-prekey", protocol: "signal-pqxdh-double-ratchet-v1", wireMessage: randomBase64(32) },
      method: "POST",
      token: thread.deliveryCapability,
    })
  );
}

await withManagedRelay(
  {
    compatibilityRoutes: true,
    envOriginName: "NOTRUS_AUTH_IDOR_RELAY_ORIGIN",
    port: Number(process.env.NOTRUS_AUTH_IDOR_PORT || 3078),
  },
  runPrimaryRegression
);

await withManagedRelay(
  {
    envOriginName: "NOTRUS_AUTH_IDOR_EXPIRY_RELAY_ORIGIN",
    extraEnv: {
      MAILBOX_CAPABILITY_TTL_MS: "3000",
      SESSION_TOKEN_TTL_MS: "3000",
    },
    port: Number(process.env.NOTRUS_AUTH_IDOR_EXPIRY_PORT || 3079),
  },
  runExpiryRegression
);

console.log("auth-idor-regression: session, event, legacy identity, revoked-device, and expired-capability checks passed");
