import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";

const relayOrigin = process.env.NOTRUS_METADATA_RELAY_ORIGIN ?? "http://127.0.0.1:3000";
const relayUrl = new URL(relayOrigin);
const storePath = process.env.NOTRUS_METADATA_STORE_PATH || new URL("../data/store.json", import.meta.url);
function isoNow() {
  return new Date().toISOString();
}

function hex(buffer) {
  return Buffer.from(buffer).toString("hex");
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

function requestJson(pathname, { method, body } = {}) {
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

async function main() {
  const suffix = randomBytes(4).toString("hex");
  const sensitiveThreadTitle = `Highly Confidential Project Umbra ${suffix}`;
  const alice = identityPayload({
    userId: `metadata-alice-${suffix}`,
    username: `metaalice${suffix}`,
    displayName: "Metadata Alice",
  });
  const bob = identityPayload({
    userId: `metadata-bob-${suffix}`,
    username: `metabob${suffix}`,
    displayName: "Metadata Bob",
  });
  const carol = identityPayload({
    userId: `metadata-carol-${suffix}`,
    username: `metacarol${suffix}`,
    displayName: "Metadata Carol",
  });
  const threadId = `metadata-thread-${suffix}`;

  const aliceRegistration = await requestJson("/api/register", { method: "POST", body: alice });
  await requestJson("/api/register", { method: "POST", body: bob });
  const carolRegistration = await requestJson("/api/register", { method: "POST", body: carol });

  await requestJson("/api/threads", {
    method: "POST",
    body: {
      createdAt: isoNow(),
      createdBy: alice.userId,
      envelopes: [],
      groupState: null,
      id: threadId,
      initialRatchetPublicJwk: null,
      mlsBootstrap: null,
      participantIds: [alice.userId, bob.userId],
      protocol: "signal-pqxdh-double-ratchet-v1",
      title: sensitiveThreadTitle,
    },
  });

  const aliceSync = await requestJson(`/api/sync?userId=${alice.userId}`, { method: "GET" });
  const syncedUsernames = new Set(aliceSync.users.map((user) => user.username));
  if (!syncedUsernames.has(alice.username) || !syncedUsernames.has(bob.username)) {
    throw new Error("Sync omitted an expected related user.");
  }
  if (syncedUsernames.has(carol.username)) {
    throw new Error("Sync leaked an unrelated directory user.");
  }

  const syncedThread = aliceSync.threads.find((thread) => thread.id === threadId);
  if (!syncedThread) {
    throw new Error("Sync omitted the newly created thread.");
  }
  if (syncedThread.title !== "") {
    throw new Error("Standards thread title was not stripped from the sync response.");
  }

  const inviteCode = carolRegistration.user.directoryCode;
  if (!inviteCode) {
    throw new Error("The relay did not return a directory invite code for the registered contact.");
  }

  const search = await requestJson(
    `/api/directory/search?userId=${alice.userId}&q=${encodeURIComponent(inviteCode)}`,
    { method: "GET" }
  );
  if (!search.results.some((result) => result.username === carol.username)) {
    throw new Error("Explicit directory search did not return the searched contact.");
  }

  const selfRecord = aliceSync.users.find((user) => user.id === alice.userId);
  if (!selfRecord?.directoryCode || selfRecord.directoryCode !== aliceRegistration.user.directoryCode) {
    throw new Error("Sync did not preserve the caller's own invite code while keeping other users' codes private.");
  }

  const store = JSON.parse(await readFile(storePath, "utf8"));
  const storedThread = store.threads?.[threadId];
  if (!storedThread) {
    throw new Error("Relay store did not persist the newly created standards thread.");
  }
  if (storedThread.title !== "") {
    throw new Error("Relay store still retained the standards-thread title for the new thread.");
  }

  console.log("metadata-boundary: sync stayed contact-scoped, search was explicit, and standards thread titles stayed off the relay");
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
