import { generateKeyPairSync, randomBytes } from "node:crypto";
import { withManagedRelay } from "./managed-relay.mjs";

function isoNow() {
  return new Date().toISOString();
}

function randomBase64(bytes = 32) {
  return randomBytes(bytes).toString("base64");
}

function generatePublicJwk() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return publicKey.export({ format: "jwk" });
}

function signalBundle() {
  return {
    deviceId: 1,
    identityKey: randomBase64(),
    kyberPreKeyId: 1,
    kyberPreKeyPublic: randomBase64(),
    kyberPreKeySignature: randomBase64(),
    preKeyId: 1,
    preKeyPublic: randomBase64(),
    registrationId: 1001,
    signedPreKeyId: 1,
    signedPreKeyPublic: randomBase64(),
    signedPreKeySignature: randomBase64(),
  };
}

function identity(username) {
  return {
    userId: `user-${randomBytes(8).toString("hex")}`,
    username,
    displayName: username,
    fingerprint: randomBytes(16).toString("hex"),
    recoveryFingerprint: randomBytes(16).toString("hex"),
    recoveryPublicJwk: generatePublicJwk(),
    signingPublicJwk: generatePublicJwk(),
    encryptionPublicJwk: generatePublicJwk(),
    prekeyCreatedAt: isoNow(),
    prekeyFingerprint: randomBytes(16).toString("hex"),
    prekeyPublicJwk: generatePublicJwk(),
    prekeySignature: randomBase64(),
    signalBundle: signalBundle(),
    device: {
      createdAt: isoNow(),
      id: `device-${randomBytes(6).toString("hex")}`,
      label: `${username}-device`,
      platform: "test",
      publicJwk: generatePublicJwk(),
      riskLevel: "low",
      storageMode: "device-only",
    },
  };
}

async function request(origin, pathname, { method = "GET", token = null, headers = {}, body = null } = {}) {
  const hasBody = body !== null && body !== undefined;
  const payload = typeof body === "string" || Buffer.isBuffer(body) ? body : hasBody ? JSON.stringify(body) : undefined;
  const response = await fetch(new URL(pathname, origin), {
    method,
    headers: {
      Accept: "application/json",
      ...(hasBody ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: payload,
  });
  const raw = await response.text();
  let decoded = raw;
  try {
    decoded = raw ? JSON.parse(raw) : {};
  } catch {
    // Keep raw body for malformed non-JSON responses.
  }
  return {
    body: decoded,
    statusCode: response.status,
  };
}

function expectStatus(label, actual, expectedStatuses) {
  if (!expectedStatuses.includes(actual.statusCode)) {
    throw new Error(`${label} returned HTTP ${actual.statusCode}, expected one of ${expectedStatuses.join(", ")}.`);
  }
}

async function run({ origin }) {
  const suffix = randomBytes(4).toString("hex");
  const alice = identity(`advalice${suffix}`);
  const bob = identity(`advbob${suffix}`);

  const aliceRegistration = await request(origin, "/api/bootstrap/register", {
    method: "POST",
    body: alice,
  });
  expectStatus("register alice", aliceRegistration, [200]);
  const bobRegistration = await request(origin, "/api/bootstrap/register", {
    method: "POST",
    body: bob,
  });
  expectStatus("register bob", bobRegistration, [200]);

  expectStatus(
    "malformed json",
    await request(origin, "/api/bootstrap/register", {
      method: "POST",
      body: "{\"displayName\":",
      headers: { "Content-Type": "application/json" },
    }),
    [400]
  );

  expectStatus(
    "wrong-type register",
    await request(origin, "/api/bootstrap/register", {
      method: "POST",
      body: { userId: 42, username: ["bad"], displayName: true },
    }),
    [400, 429]
  );

  const search = await request(origin, `/api/directory/search?q=${encodeURIComponent(bob.username)}`, {
    token: aliceRegistration.body.session.token,
  });
  expectStatus("directory search", search, [200]);
  const bobResult = search.body.results.find((candidate) => candidate.username === bob.username);
  if (!bobResult?.contactHandle) {
    throw new Error("Directory search did not return Bob's contact handle.");
  }

  expectStatus(
    "invalid thread create",
    await request(origin, "/api/routing/threads", {
      method: "POST",
      token: aliceRegistration.body.session.token,
      body: {
        createdAt: isoNow(),
        id: `adversarial-invalid-thread-${suffix}`,
        participantHandles: [],
        protocol: "signal-pqxdh-double-ratchet-v1",
        title: "",
      },
    }),
    [400]
  );

  const validThread = await request(origin, "/api/routing/threads", {
    method: "POST",
    token: aliceRegistration.body.session.token,
    body: {
      createdAt: isoNow(),
      id: `adversarial-thread-${suffix}`,
      participantHandles: [bobResult.contactHandle],
      protocol: "signal-pqxdh-double-ratchet-v1",
      title: "",
    },
  });
  expectStatus("valid thread create", validThread, [200, 201]);

  const sync = await request(origin, "/api/sync/state", {
    token: aliceRegistration.body.session.token,
  });
  expectStatus("sync", sync, [200]);
  const thread = sync.body.threads.find((candidate) => candidate.id === validThread.body.threadId);
  if (!thread?.mailboxHandle || !thread?.deliveryCapability) {
    throw new Error("Sync did not return mailbox routing state.");
  }

  expectStatus(
    "invalid attachment",
    await request(origin, `/api/mailboxes/${thread.mailboxHandle}/attachments`, {
      method: "POST",
      token: thread.deliveryCapability,
      body: {
        byteLength: -1,
        ciphertext: "x",
        createdAt: isoNow(),
        id: `attachment-${suffix}`,
        iv: "bad",
        sha256: "bad",
      },
    }),
    [400]
  );

  expectStatus(
    "invalid report target thread mismatch",
    await request(origin, "/api/reports", {
      method: "POST",
      token: aliceRegistration.body.session.token,
      body: {
        createdAt: isoNow(),
        messageIds: ["message-1"],
        reason: "abuse-or-spam",
        reporterId: alice.userId,
        targetUserId: bob.userId,
        threadId: "non-existent-thread",
      },
    }),
    [404]
  );

  expectStatus(
    "valid minimal report",
    await request(origin, "/api/reports", {
      method: "POST",
      token: aliceRegistration.body.session.token,
      body: {
        createdAt: isoNow(),
        messageIds: ["message-1", "message-2"],
        reason: "abuse-or-spam",
        reporterId: alice.userId,
        targetUserId: bob.userId,
        threadId: validThread.body.threadId,
      },
    }),
    [200]
  );

  for (let index = 0; index < 25; index += 1) {
    const mutated = randomBase64(24);
    const response = await request(origin, "/api/reports", {
      method: "POST",
      token: aliceRegistration.body.session.token,
      body: {
        createdAt: index % 2 === 0 ? isoNow() : mutated,
        messageIds: Array.from({ length: 4 }, () => mutated),
        reason: index % 3 === 0 ? "abuse-or-spam" : mutated,
        reporterId: index % 4 === 0 ? alice.userId : mutated,
        targetUserId: bob.userId,
        threadId: index % 5 === 0 ? validThread.body.threadId : mutated,
      },
    });
    if (![200, 400, 403, 404, 429].includes(response.statusCode)) {
      throw new Error(`mutated report ${index} returned unexpected HTTP ${response.statusCode}`);
    }
  }

  const health = await request(origin, "/api/health");
  expectStatus("health", health, [200]);
  if (!health.body?.ok) {
    throw new Error("Relay health degraded after adversarial inputs.");
  }

  if (!bobRegistration.body.session?.token) {
    throw new Error("Bob registration did not issue a session token.");
  }

  console.log("adversarial-inputs: malformed and mutated relay requests stayed bounded without crashing the relay");
}

withManagedRelay(
  {
    envOriginName: "NOTRUS_ADVERSARIAL_RELAY_ORIGIN",
    port: Number(process.env.NOTRUS_ADVERSARIAL_INPUTS_PORT || 3067),
  },
  run
).catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
