import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = fileURLToPath(new URL("..", import.meta.url));

function isoNow() {
  return new Date().toISOString();
}

function isoAgo(ms) {
  return new Date(Date.now() - ms).toISOString();
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

function hex(buffer) {
  return Buffer.from(buffer).toString("hex");
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

function identityPayload({ userId, username, displayName, deviceId }) {
  return {
    displayName,
    encryptionPublicJwk: generateJwk(),
    fingerprint: hex(randomBytes(16)),
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
    device: {
      createdAt: isoNow(),
      id: deviceId,
      label: `${username}-device`,
      platform: "android",
      publicJwk: generateJwk(),
      riskLevel: "low",
      storageMode: "strongbox",
    },
  };
}

function requestJson(origin, pathname, { method = "GET", headers = {}, body = null } = {}) {
  const url = new URL(pathname, origin);
  const payload = body ? Buffer.from(JSON.stringify(body), "utf8") : null;

  return new Promise((resolve, reject) => {
    const request = http.request(
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
          const decoded = raw ? JSON.parse(raw) : {};
          if ((response.statusCode ?? 500) < 200 || (response.statusCode ?? 500) > 299) {
            reject(new Error(`${pathname} failed: ${response.statusCode} ${decoded.error ?? raw}`));
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

async function waitForHealth(origin) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      await requestJson(origin, "/api/health");
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error("Timed out waiting for the retention relay.");
}

function startRelay({ port, storePath, secretDir }) {
  const child = spawn(process.execPath, ["server.js"], {
    cwd: rootDir,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: "127.0.0.1",
      NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES: "true",
      NOTRUS_STORE_PATH: storePath,
      NOTRUS_SECRET_DIR: secretDir,
      MESSAGE_RETENTION_MS: "1000",
      ATTACHMENT_RETENTION_MS: "1000",
      REPORT_RETENTION_MS: "1000",
      DEVICE_EVENT_RETENTION_MS: "1000",
    },
    stdio: "ignore",
  });
  return child;
}

async function stopRelay(child) {
  if (!child) {
    return;
  }
  child.kill("SIGTERM");
  await new Promise((resolve) => child.once("exit", resolve));
}

async function main() {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "notrus-retention-"));
  const storePath = path.join(tempRoot, "store.json");
  const secretDir = path.join(tempRoot, "secrets");
  const port = 3064;
  const origin = `http://127.0.0.1:${port}`;
  const suffix = randomBytes(4).toString("hex");
  const alice = identityPayload({
    userId: `retention-alice-${suffix}`,
    username: `retalice${suffix}`,
    displayName: "Retention Alice",
    deviceId: `device-alice-${suffix}`,
  });
  const bob = identityPayload({
    userId: `retention-bob-${suffix}`,
    username: `retbob${suffix}`,
    displayName: "Retention Bob",
    deviceId: `device-bob-${suffix}`,
  });
  const threadId = `retention-thread-${suffix}`;
  const messageId = `retention-message-${suffix}`;
  const attachmentId = `retention-attachment-${suffix}`;

  let relay = startRelay({ port, storePath, secretDir });
  try {
    await waitForHealth(origin);

    const aliceRegistration = await requestJson(origin, "/api/register", {
      method: "POST",
      headers: { "X-Notrus-Device-Id": alice.device.id },
      body: alice,
    });
    await requestJson(origin, "/api/register", {
      method: "POST",
      headers: { "X-Notrus-Device-Id": bob.device.id },
      body: bob,
    });

    await requestJson(origin, "/api/threads", {
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
        title: "",
      },
    });

    await requestJson(origin, `/api/threads/${threadId}/messages`, {
      method: "POST",
      body: {
        createdAt: isoNow(),
        id: messageId,
        messageKind: "signal-whisper",
        protocol: "signal-pqxdh-double-ratchet-v1",
        senderId: alice.userId,
        threadId,
        wireMessage: randomBytes(96).toString("base64"),
      },
    });

    await requestJson(origin, `/api/threads/${threadId}/attachments`, {
      method: "POST",
      body: {
        byteLength: 256,
        ciphertext: randomBytes(256).toString("base64"),
        createdAt: isoNow(),
        id: attachmentId,
        iv: randomBytes(12).toString("base64"),
        senderId: alice.userId,
        sha256: hex(randomBytes(32)),
        threadId,
      },
    });

    await requestJson(origin, "/api/reports", {
      method: "POST",
      headers: { Authorization: `Bearer ${aliceRegistration.session.token}` },
      body: {
        createdAt: isoNow(),
        messageIds: [messageId],
        reason: "spam",
        reporterId: alice.userId,
        targetUserId: bob.userId,
        threadId,
      },
    });

    await stopRelay(relay);
    relay = null;

    const seededStore = JSON.parse(await readFile(storePath, "utf8"));
    seededStore.threads[threadId].messages[0].createdAt = isoAgo(10_000);
    seededStore.threads[threadId].attachments[0].createdAt = isoAgo(10_000);
    seededStore.reports[0].createdAt = isoAgo(10_000);
    seededStore.users[alice.userId].deviceEvents = (seededStore.users[alice.userId].deviceEvents ?? []).map((event) => ({
      ...event,
      createdAt: isoAgo(10_000),
    }));
    await writeFile(storePath, JSON.stringify(seededStore, null, 2), "utf8");

    relay = startRelay({ port, storePath, secretDir });
    await waitForHealth(origin);
    await requestJson(origin, `/api/sync?userId=${alice.userId}`);
    await stopRelay(relay);
    relay = null;

    const prunedStore = JSON.parse(await readFile(storePath, "utf8"));
    assert.equal(prunedStore.threads[threadId].messages.length, 0, "expired ciphertext messages should be pruned");
    assert.equal(prunedStore.threads[threadId].attachments.length, 0, "expired ciphertext attachments should be pruned");
    assert.equal(prunedStore.reports.length, 0, "expired abuse reports should be pruned");
    assert.equal((prunedStore.users[alice.userId].deviceEvents ?? []).length, 0, "expired device events should be pruned");

    console.log("retention-pruning: relay pruned expired message, attachment, report, and device-event artifacts");
  } finally {
    await stopRelay(relay);
    await rm(tempRoot, { force: true, recursive: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
