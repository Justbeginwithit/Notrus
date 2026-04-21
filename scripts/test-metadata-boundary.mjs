import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
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

async function request(origin, pathname, { method = "GET", token = null, body } = {}) {
  const response = await fetch(new URL(pathname, origin), {
    method,
    headers: {
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`${method} ${pathname} failed: ${response.status} ${payload.error ?? JSON.stringify(payload)}`);
  }
  return payload;
}

async function run({ origin, storePath }) {
  const suffix = randomBytes(4).toString("hex");
  const sensitiveThreadTitle = `Highly Confidential Metadata ${suffix}`;
  const alice = identity(`metaalice${suffix}`);
  const bob = identity(`metabob${suffix}`);
  const carol = identity(`metacarol${suffix}`);

  const aliceRegistration = await request(origin, "/api/bootstrap/register", {
    method: "POST",
    headers: { "X-Notrus-Device-Id": alice.device.id },
    body: alice,
  });
  const bobRegistration = await request(origin, "/api/bootstrap/register", {
    method: "POST",
    headers: { "X-Notrus-Device-Id": bob.device.id },
    body: bob,
  });
  const carolRegistration = await request(origin, "/api/bootstrap/register", {
    method: "POST",
    headers: { "X-Notrus-Device-Id": carol.device.id },
    body: carol,
  });

  const bobSearch = await request(origin, `/api/directory/search?q=${encodeURIComponent(bob.username)}`, {
    token: aliceRegistration.session.token,
  });
  const bobResult = bobSearch.results.find((candidate) => candidate.username === bob.username);
  assert.ok(bobResult?.contactHandle, "Directory search should return Bob as an opaque contact handle.");

  const thread = await request(origin, "/api/routing/threads", {
    method: "POST",
    token: aliceRegistration.session.token,
    body: {
      createdAt: isoNow(),
      id: `metadata-thread-${suffix}`,
      participantHandles: [bobResult.contactHandle],
      protocol: "signal-pqxdh-double-ratchet-v1",
      title: sensitiveThreadTitle,
    },
  });

  const aliceSync = await request(origin, "/api/sync/state", {
    token: aliceRegistration.session.token,
  });
  const syncedUsernames = new Set(aliceSync.users.map((user) => user.username));
  assert.equal(syncedUsernames.has(alice.username), true, "Sync omitted the local user.");
  assert.equal(syncedUsernames.has(bob.username), true, "Sync omitted the related user.");
  assert.equal(syncedUsernames.has(carol.username), false, "Sync leaked an unrelated directory user.");

  const syncedThread = aliceSync.threads.find((candidate) => candidate.id === thread.threadId);
  assert.ok(syncedThread, "Sync omitted the newly created thread.");
  assert.equal(syncedThread.title, "", "Standards thread title should be stripped from sync.");

  const inviteCode = carolRegistration.user.directoryCode;
  assert.ok(inviteCode, "Registration should return the user's own invite code.");
  const inviteSearch = await request(origin, `/api/directory/search?q=${encodeURIComponent(inviteCode)}`, {
    token: aliceRegistration.session.token,
  });
  assert.equal(
    inviteSearch.results.some((result) => result.username === carol.username),
    true,
    "Explicit invite-code search did not return the searched contact."
  );

  const selfRecord = aliceSync.users.find((user) => user.id === alice.userId);
  assert.equal(selfRecord?.directoryCode, aliceRegistration.user.directoryCode, "Sync should preserve the caller's own invite code.");
  assert.equal(
    aliceSync.users.some((user) => user.id === bob.userId && "directoryCode" in user),
    false,
    "Sync should not reveal other users' invite codes."
  );

  if (storePath) {
    const store = JSON.parse(await readFile(storePath, "utf8"));
    const storedThread = store.threads?.[thread.threadId];
    assert.ok(storedThread, "Relay store did not persist the newly created standards thread.");
    assert.equal(storedThread.title, "", "Relay store retained a standards-thread title.");
    assert.equal(JSON.stringify(storedThread).includes(sensitiveThreadTitle), false, "Relay store retained the sensitive thread title.");
  }

  assert.ok(bobRegistration.session?.token, "Bob registration should issue a session token.");
  console.log("metadata-boundary: sync stayed contact-scoped, search was explicit, and standards thread titles stayed off the relay");
}

withManagedRelay(
  {
    envOriginName: "NOTRUS_METADATA_RELAY_ORIGIN",
    port: Number(process.env.NOTRUS_METADATA_BOUNDARY_PORT || 3064),
  },
  run
).catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
