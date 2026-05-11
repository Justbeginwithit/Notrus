import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { withManagedRelay } from "./managed-relay.mjs";

const plaintextAttachment = Buffer.from("server should never store this plaintext attachment", "utf8");

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
  return { payload, response, status: response.status };
}

async function expectOk(origin, pathname, options) {
  const result = await request(origin, pathname, options);
  assert.equal(result.response.ok, true, `${options?.method ?? "GET"} ${pathname} returned ${result.status}`);
  return result.payload;
}

async function encryptAttachment(plaintext, { attachmentId, senderId, threadId }) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = randomBytes(12);
  const aad = Buffer.from(
    JSON.stringify({
      attachmentId,
      createdAt: isoNow(),
      kind: "notrus-attachment",
      senderId,
      threadId,
    }),
    "utf8"
  );
  const encrypted = Buffer.from(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      plaintext
    )
  );
  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    sha256: createHash("sha256").update(Buffer.concat([iv, encrypted])).digest("hex"),
  };
}

function encryptedChunk(index, byteLength = 32) {
  const iv = randomBytes(12);
  const ciphertext = randomBytes(byteLength + 16);
  return {
    byteLength,
    ciphertext: ciphertext.toString("base64"),
    index,
    iv: iv.toString("base64"),
    sha256: createHash("sha256").update(Buffer.concat([iv, ciphertext])).digest("hex"),
  };
}

async function run({ origin, storePath }) {
  const suffix = randomBytes(4).toString("hex");
  const alice = identity(`contentalice${suffix}`);
  const bob = identity(`contentbob${suffix}`);

  const aliceRegistration = await expectOk(origin, "/api/bootstrap/register", {
    method: "POST",
    body: alice,
  });
  const bobRegistration = await expectOk(origin, "/api/bootstrap/register", {
    method: "POST",
    body: bob,
  });

  const search = await expectOk(origin, `/api/directory/search?q=${encodeURIComponent(bob.username)}`, {
    token: aliceRegistration.session.token,
  });
  const bobResult = search.results.find((candidate) => candidate.username === bob.username);
  assert.ok(bobResult?.contactHandle, "Directory search should return an opaque contact handle.");

  const thread = await expectOk(origin, "/api/routing/threads", {
    method: "POST",
    token: aliceRegistration.session.token,
    body: {
      createdAt: isoNow(),
      id: `content-thread-${suffix}`,
      participantHandles: [bobResult.contactHandle],
      protocol: "signal-pqxdh-double-ratchet-v1",
      title: "",
    },
  });

  const aliceSync = await expectOk(origin, "/api/sync/state", { token: aliceRegistration.session.token });
  const aliceThread = aliceSync.threads.find((candidate) => candidate.id === thread.threadId);
  assert.ok(aliceThread?.mailboxHandle, "Alice sync should return a mailbox handle.");
  assert.ok(aliceThread?.deliveryCapability, "Alice sync should return a delivery capability.");

  const messageId = `content-message-${suffix}`;
  await expectOk(origin, `/api/mailboxes/${aliceThread.mailboxHandle}/messages`, {
    method: "POST",
    token: aliceThread.deliveryCapability,
    body: {
      createdAt: isoNow(),
      id: messageId,
      messageKind: "signal-whisper",
      protocol: "signal-pqxdh-double-ratchet-v1",
      wireMessage: randomBase64(96),
    },
  });

  const attachmentId = `content-attachment-${suffix}`;
  const sealedAttachment = await encryptAttachment(plaintextAttachment, {
    attachmentId,
    senderId: alice.userId,
    threadId: thread.threadId,
  });
  await expectOk(origin, `/api/mailboxes/${aliceThread.mailboxHandle}/attachments`, {
    method: "POST",
    token: aliceThread.deliveryCapability,
    body: {
      byteLength: plaintextAttachment.length,
      ciphertext: sealedAttachment.ciphertext,
      createdAt: isoNow(),
      id: attachmentId,
      iv: sealedAttachment.iv,
      sha256: sealedAttachment.sha256,
    },
  });

  const bobSync = await expectOk(origin, "/api/sync/state", { token: bobRegistration.session.token });
  const bobThread = bobSync.threads.find((candidate) => candidate.id === thread.threadId);
  assert.ok(bobThread?.mailboxHandle, "Bob sync should return a mailbox handle.");
  assert.ok(bobThread?.deliveryCapability, "Bob sync should return a delivery capability.");

  const fetchedAttachment = await expectOk(
    origin,
    `/api/mailboxes/${bobThread.mailboxHandle}/attachments/${attachmentId}`,
    { token: bobThread.deliveryCapability }
  );
  assert.equal(fetchedAttachment.ciphertext, sealedAttachment.ciphertext, "Fetched attachment ciphertext should match upload.");

  const chunkedAttachmentId = `content-chunked-${suffix}`;
  const firstChunk = encryptedChunk(0, 64);
  const secondChunk = encryptedChunk(1, 48);
  const manifestSha256 = createHash("sha256")
    .update(`${firstChunk.sha256}:${secondChunk.sha256}`)
    .digest("hex");
  await expectOk(origin, `/api/mailboxes/${aliceThread.mailboxHandle}/attachments`, {
    method: "POST",
    token: aliceThread.deliveryCapability,
    body: {
      byteLength: firstChunk.byteLength + secondChunk.byteLength,
      chunkCount: 2,
      chunkSize: 64,
      chunks: [
        {
          byteLength: firstChunk.byteLength,
          index: firstChunk.index,
          iv: firstChunk.iv,
          sha256: firstChunk.sha256,
        },
        {
          byteLength: secondChunk.byteLength,
          index: secondChunk.index,
          iv: secondChunk.iv,
          sha256: secondChunk.sha256,
        },
      ],
      createdAt: isoNow(),
      id: chunkedAttachmentId,
      sha256: manifestSha256,
      transport: "chunked-aes-gcm-v1",
    },
  });
  for (const chunk of [firstChunk, secondChunk]) {
    await expectOk(origin, `/api/mailboxes/${aliceThread.mailboxHandle}/attachments/${chunkedAttachmentId}/chunks`, {
      method: "POST",
      token: aliceThread.deliveryCapability,
      body: chunk,
    });
  }
  const fetchedChunkedManifest = await expectOk(
    origin,
    `/api/mailboxes/${bobThread.mailboxHandle}/attachments/${chunkedAttachmentId}`,
    { token: bobThread.deliveryCapability }
  );
  assert.equal(fetchedChunkedManifest.transport, "chunked-aes-gcm-v1", "Chunked attachment manifest should round-trip.");
  assert.equal(fetchedChunkedManifest.ciphertext, undefined, "Chunked attachment manifest should not inline ciphertext.");
  assert.equal(fetchedChunkedManifest.chunks.length, 2, "Chunked attachment manifest should include chunk descriptors.");
  const fetchedChunk = await expectOk(
    origin,
    `/api/mailboxes/${bobThread.mailboxHandle}/attachments/${chunkedAttachmentId}/chunks/1`,
    { token: bobThread.deliveryCapability }
  );
  assert.equal(fetchedChunk.ciphertext, secondChunk.ciphertext, "Fetched encrypted chunk should match upload.");

  const unauthorizedFetch = await request(
    origin,
    `/api/mailboxes/${bobThread.mailboxHandle}/attachments/${attachmentId}`,
    { token: bobRegistration.session.token }
  );
  assert.equal(unauthorizedFetch.status, 401, "Attachment fetch should require a mailbox capability, not a session token.");

  if (storePath) {
    const store = await readFile(storePath, "utf8");
    assert.equal(store.includes(plaintextAttachment.toString("utf8")), false, "Relay store contains plaintext attachment data.");
    assert.equal(store.includes(sealedAttachment.ciphertext), true, "Relay store should contain only encrypted attachment material.");
    assert.equal(store.includes(firstChunk.ciphertext), false, "Relay store should not inline chunked attachment payloads.");
  }

  console.log("content-boundary: relay stored ciphertext-only message and attachment material");
}

withManagedRelay(
  {
    envOriginName: "NOTRUS_CONTENT_RELAY_ORIGIN",
    port: Number(process.env.NOTRUS_CONTENT_BOUNDARY_PORT || 3065),
  },
  run
).catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
