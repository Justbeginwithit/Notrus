import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";

const relayOrigin = process.env.NOTRUS_CONTENT_RELAY_ORIGIN ?? "http://127.0.0.1:3000";
const relayUrl = new URL(relayOrigin);
const storePath = process.env.NOTRUS_CONTENT_STORE_PATH || null;
const plaintextAttachment = Buffer.from("server should never store this plaintext attachment", "utf8");

function isoNow() {
  return new Date().toISOString();
}

function hex(buffer) {
  return Buffer.from(buffer).toString("hex");
}

function base64url(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function generateJwk() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  return {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };
}

function fakeSignalBundle() {
  const bytes = () => randomBytes(32).toString("base64");
  return {
    deviceId: 1,
    identityKey: bytes(),
    kyberPreKeyId: 1,
    kyberPreKeyPublic: bytes(),
    kyberPreKeySignature: bytes(),
    preKeyId: 1,
    preKeyPublic: bytes(),
    registrationId: 42,
    signedPreKeyId: 1,
    signedPreKeyPublic: bytes(),
    signedPreKeySignature: bytes(),
  };
}

function identityPayload({ userId, username, displayName }) {
  return {
    displayName,
    encryptionPublicJwk: generateJwk(),
    fingerprint: hex(randomBytes(16)),
    mlsKeyPackage: null,
    prekeyCreatedAt: isoNow(),
    prekeyFingerprint: hex(randomBytes(16)),
    prekeyPublicJwk: generateJwk(),
    prekeySignature: randomBytes(64).toString("base64"),
    recoveryFingerprint: hex(randomBytes(16)),
    recoveryPublicJwk: generateJwk(),
    signalBundle: fakeSignalBundle(),
    signingPublicJwk: generateJwk(),
    userId,
    username,
  };
}

async function post(pathname, body) {
  return requestJson(pathname, {
    method: "POST",
    body,
  });
}

async function get(pathname) {
  return requestJson(pathname, { method: "GET" });
}

function requestJson(pathname, { method, body }) {
  const url = new URL(pathname, relayUrl);
  const client = url.protocol === "https:" ? https : http;
  const payload = body ? Buffer.from(JSON.stringify(body), "utf8") : null;

  return new Promise((resolve, reject) => {
    const request = client.request(
      url,
      {
        method,
        headers: payload
          ? {
              "Content-Length": String(payload.length),
              "Content-Type": "application/json",
            }
          : {},
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          const decoded = raw ? JSON.parse(raw) : {};
          if ((response.statusCode ?? 500) < 200 || (response.statusCode ?? 500) > 299) {
            reject(new Error(`${pathname} failed: ${response.statusCode} ${decoded.error ?? "unknown error"}`));
            return;
          }
          resolve(decoded);
        });
      }
    );

    request.on("error", reject);
    if (payload) {
      request.write(payload);
    }
    request.end();
  });
}

async function encryptAttachment(plaintext, { attachmentId, senderId, threadId }) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const rawKey = Buffer.from(await crypto.subtle.exportKey("raw", key));
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
    attachmentKey: rawKey.toString("base64"),
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    sha256: createHash("sha256").update(Buffer.concat([iv, encrypted])).digest("hex"),
  };
}

async function main() {
  const suffix = randomBytes(4).toString("hex");
  const aliceUserId = `content-boundary-alice-${suffix}`;
  const bobUserId = `content-boundary-bob-${suffix}`;
  const threadId = `content-boundary-thread-${suffix}`;
  const attachmentId = `content-boundary-attachment-${suffix}`;
  const messageId = `content-boundary-message-${suffix}`;
  const alice = identityPayload({
    userId: aliceUserId,
    username: `contentalice${suffix}`,
    displayName: "Content Boundary Alice",
  });
  const bob = identityPayload({
    userId: bobUserId,
    username: `contentbob${suffix}`,
    displayName: "Content Boundary Bob",
  });

  await post("/api/register", alice);
  await post("/api/register", bob);

  await post("/api/threads", {
    createdAt: isoNow(),
    createdBy: alice.userId,
    envelopes: [],
    groupState: null,
    id: threadId,
    initialRatchetPublicJwk: null,
    mlsBootstrap: null,
    participantIds: [alice.userId, bob.userId],
    protocol: "signal-pqxdh-double-ratchet-v1",
    title: "Content Boundary",
  });

  await post(`/api/threads/${threadId}/messages`, {
    createdAt: isoNow(),
    id: messageId,
    messageKind: "signal-whisper",
    protocol: "signal-pqxdh-double-ratchet-v1",
    senderId: alice.userId,
    threadId,
    wireMessage: randomBytes(96).toString("base64"),
  });

  const sealedAttachment = await encryptAttachment(plaintextAttachment, {
    attachmentId,
    senderId: alice.userId,
    threadId,
  });
  await post(`/api/threads/${threadId}/attachments`, {
    byteLength: plaintextAttachment.length,
    ciphertext: sealedAttachment.ciphertext,
    createdAt: isoNow(),
    id: attachmentId,
    iv: sealedAttachment.iv,
    senderId: alice.userId,
    sha256: sealedAttachment.sha256,
    threadId,
  });

  const fetchedAttachment = await get(
    `/api/threads/${threadId}/attachments/${attachmentId}?userId=${bob.userId}`
  );
  if (fetchedAttachment.ciphertext !== sealedAttachment.ciphertext) {
    throw new Error("Fetched attachment ciphertext did not match the uploaded ciphertext.");
  }

  await expectUnauthorized(`/api/threads/${threadId}/attachments/${attachmentId}?userId=outsider`);

  const store = await readFile(storePath ?? new URL("./data/store.json", import.meta.url), "utf8").catch(async () => {
    return readFile(new URL("../data/store.json", import.meta.url), "utf8");
  });

  if (store.includes(plaintextAttachment.toString("utf8"))) {
    throw new Error("Relay store contains the plaintext attachment.");
  }

  console.log("content-boundary: relay stored ciphertext-only message and attachment material");
}

function expectUnauthorized(pathname) {
  const url = new URL(pathname, relayUrl);
  const client = url.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.request(url, { method: "GET" }, (response) => {
      if (response.statusCode !== 403) {
        reject(new Error(`Expected unauthorized attachment fetch to return 403, received ${response.statusCode}.`));
        return;
      }
      resolve();
    });
    request.on("error", reject);
    request.end();
  });
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
