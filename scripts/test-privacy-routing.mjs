import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";

const relayOrigin = process.env.NOTRUS_PRIVACY_RELAY_ORIGIN ?? "http://127.0.0.1:3060";

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

async function request(path, { method = "GET", token = null, headers = {}, body } = {}) {
  const response = await fetch(new URL(path, relayOrigin), {
    method,
    headers: {
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`${method} ${path} failed: ${response.status} ${payload.error ?? JSON.stringify(payload)}`);
  }
  return payload;
}

async function main() {
  const suffix = randomBytes(4).toString("hex");
  const alice = identity(`alice_${suffix}`);
  const bob = identity(`bob_${suffix}`);

  const aliceRegistration = await request("/api/bootstrap/register", {
    method: "POST",
    headers: {
      "X-Notrus-Device-Id": alice.device.id,
      "X-Notrus-Instance-Id": "privacy-test-alice",
      "X-Notrus-Integrity": Buffer.from(JSON.stringify({
        bundleIdentifier: "com.notrus.test",
        codeSignatureStatus: "debug",
        deviceCheckStatus: "local-test",
        deviceCheckTokenPresented: false,
        generatedAt: isoNow(),
        riskLevel: "low",
      })).toString("base64"),
    },
    body: alice,
  });
  const bobRegistration = await request("/api/bootstrap/register", {
    method: "POST",
    headers: {
      "X-Notrus-Device-Id": bob.device.id,
      "X-Notrus-Instance-Id": "privacy-test-bob",
      "X-Notrus-Integrity": Buffer.from(JSON.stringify({
        bundleIdentifier: "com.notrus.test",
        codeSignatureStatus: "debug",
        deviceCheckStatus: "local-test",
        deviceCheckTokenPresented: false,
        generatedAt: isoNow(),
        riskLevel: "low",
      })).toString("base64"),
    },
    body: bob,
  });

  assert.ok(aliceRegistration.session?.token, "bootstrap register should issue a session token");
  assert.ok(bobRegistration.session?.token, "bootstrap register should issue a session token");

  const aliceSyncBefore = await request("/api/sync/state", {
    token: aliceRegistration.session.token,
  });
  assert.ok(Array.isArray(aliceSyncBefore.users), "sync should return scoped users");
  assert.ok(Array.isArray(aliceSyncBefore.threads), "sync should return scoped threads");
  assert.equal("deviceEvents" in aliceSyncBefore, false, "routine sync should not carry device state");
  assert.equal("transparencyEntries" in aliceSyncBefore, false, "routine sync should not carry transparency state");
  assert.equal("relayTime" in aliceSyncBefore, false, "routine sync should not echo timing metadata");

  const aliceSearch = await request(`/api/directory/search?q=${encodeURIComponent(bob.username)}`, {
    token: aliceRegistration.session.token,
  });
  assert.equal(aliceSearch.mode, "opaque-contact-handle-v1");
  assert.equal("query" in aliceSearch, false, "directory search should not echo the requested query");
  const bobSearchResult = aliceSearch.results.find((user) => user.username === bob.username);
  assert.ok(bobSearchResult?.contactHandle, "directory search should return opaque contact handles");
  assert.equal("contactHandleExpiresAt" in bobSearchResult, false, "directory search should not echo contact-handle expiry");

  const threadCreateBody = {
    createdAt: isoNow(),
    id: `thread-${randomBytes(8).toString("hex")}`,
    participantHandles: [bobSearchResult.contactHandle],
    protocol: "signal-pqxdh-double-ratchet-v1",
    title: "",
  };
  assert.equal("participantIds" in threadCreateBody, false, "thread create body should not include raw participant ids");
  assert.equal("createdBy" in threadCreateBody, false, "thread create body should not include raw creator ids");

  const threadCreated = await request("/api/routing/threads", {
    method: "POST",
    token: aliceRegistration.session.token,
    body: threadCreateBody,
  });
  assert.ok(threadCreated.threadId, "thread creation should succeed");

  const aliceSyncAfter = await request("/api/sync/state", {
    token: aliceRegistration.session.token,
  });
  const createdThread = aliceSyncAfter.threads.find((thread) => thread.id === threadCreated.threadId);
  assert.ok(createdThread?.mailboxHandle, "sync should return an opaque mailbox handle");
  assert.ok(createdThread?.deliveryCapability, "sync should return a delivery capability token");
  assert.equal("mailboxHandleExpiresAt" in createdThread, false, "sync should not echo mailbox handle expiry");
  assert.equal("deliveryCapabilityExpiresAt" in createdThread, false, "sync should not echo delivery capability expiry");

  const messageBody = {
    createdAt: isoNow(),
    id: `msg-${randomBytes(8).toString("hex")}`,
    messageKind: "signal-prekey",
    protocol: "signal-pqxdh-double-ratchet-v1",
    wireMessage: randomBase64(48),
  };
  assert.equal("senderId" in messageBody, false, "message body should not include senderId");
  assert.equal("threadId" in messageBody, false, "message body should not include threadId");

  const messagePosted = await request(`/api/mailboxes/${createdThread.mailboxHandle}/messages`, {
    method: "POST",
    token: createdThread.deliveryCapability,
    body: messageBody,
  });
  assert.ok(messagePosted.messageId, "mailbox delivery should return a receipt id");

  const devices = await request("/api/security/devices", {
    token: aliceRegistration.session.token,
  });
  assert.ok(Array.isArray(devices.devices), "device snapshot endpoint should be separate from routine sync");

  const transparency = await request("/api/security/transparency", {
    token: aliceRegistration.session.token,
  });
  assert.ok(Array.isArray(transparency.transparencyEntries), "transparency state should be separate from routine sync");

  console.log(JSON.stringify({
    checks: [
      "bootstrap-session-issued",
      "routine-sync-minimal",
      "opaque-contact-handles",
      "handle-based-thread-create",
      "mailbox-based-message-delivery",
      "separate-device-transparency-endpoints",
    ],
    relayOrigin,
    threadId: threadCreated.threadId,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
