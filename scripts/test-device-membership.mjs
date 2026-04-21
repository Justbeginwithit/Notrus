import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { fileURLToPath } from "node:url";
import http from "node:http";
import https from "node:https";
import path from "node:path";

const rootDir = fileURLToPath(new URL("..", import.meta.url));
const relayOrigin = process.env.NOTRUS_DEVICE_MODEL_RELAY_ORIGIN ?? "http://127.0.0.1:3017";
const relayUrl = new URL(relayOrigin);
const relayPort = Number(relayUrl.port || 3017);
const managedRelay = !process.env.NOTRUS_DEVICE_MODEL_RELAY_ORIGIN;
const dataDir = process.env.NOTRUS_DEVICE_MODEL_DATA_DIR ?? path.join("/tmp", `notrus-device-model-${process.pid}`);
let relayProcess = null;

function isoNow() {
  return new Date().toISOString();
}

function hex(buffer) {
  return Buffer.from(buffer).toString("hex");
}

function generateEcKeyMaterial() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
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

function createIdentity({ userId, username, displayName }) {
  const signing = generateEcKeyMaterial();
  const encryption = generateEcKeyMaterial();
  const recovery = generateEcKeyMaterial();
  const prekey = generateEcKeyMaterial();

  return {
    accountKeys: { signing, encryption, recovery, prekey },
    payload: {
      createdAt: isoNow(),
      displayName,
      encryptionPublicJwk: encryption.publicJwk,
      fingerprint: hex(randomBytes(16)),
      mlsKeyPackage: null,
      prekeyCreatedAt: isoNow(),
      prekeyFingerprint: hex(randomBytes(16)),
      prekeyPublicJwk: prekey.publicJwk,
      prekeySignature: randomBytes(64).toString("base64"),
      recoveryFingerprint: hex(randomBytes(16)),
      recoveryPublicJwk: recovery.publicJwk,
      signalBundle: fakeSignalBundle(),
      signingPublicJwk: signing.publicJwk,
      userId,
      username,
    },
  };
}

function createDevice(label, platform = "test-device") {
  const signing = generateEcKeyMaterial();
  return {
    descriptor: {
      createdAt: isoNow(),
      id: `device-${randomBytes(6).toString("hex")}`,
      label,
      platform,
      publicJwk: signing.publicJwk,
      riskLevel: "low",
      storageMode: "test-device-key",
    },
    privateKey: signing.privateKey,
  };
}

function signPayload(privateKey, payload) {
  const signer = createSign("sha256");
  signer.update(payload);
  signer.end();
  return signer.sign(privateKey).toString("base64");
}

function request(pathname, { method = "GET", headers = {}, body = null } = {}) {
  const url = new URL(pathname, relayUrl);
  const client = url.protocol === "https:" ? https : http;
  const payload = body == null ? null : Buffer.from(JSON.stringify(body), "utf8");

  return new Promise((resolve, reject) => {
    const req = client.request(
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
          resolve({ body: decoded, statusCode: response.statusCode ?? 0 });
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

function isAccessDenied(statusCode) {
  return statusCode === 401 || statusCode === 403;
}

async function waitForHealth() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await request("/api/health");
      if (response.statusCode === 200) {
        return;
      }
    } catch {
      // wait
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Timed out waiting for the device-model relay.");
}

async function startRelay() {
  await fs.mkdir(dataDir, { recursive: true });
  relayProcess = spawn(process.execPath, ["server.js"], {
    cwd: rootDir,
    env: {
      ...process.env,
      PORT: String(relayPort),
      NOTRUS_DATA_DIR: dataDir,
      NOTRUS_PROTOCOL_POLICY: "require-standards",
    },
    stdio: "ignore",
  });
  await waitForHealth();
}

async function stopRelay() {
  if (!relayProcess) {
    return;
  }
  relayProcess.kill("SIGTERM");
  relayProcess = null;
}

async function main() {
  process.on("exit", () => {
    if (relayProcess) {
      relayProcess.kill("SIGTERM");
    }
  });

  if (managedRelay) {
    await startRelay();
  }

  try {
    const suffix = randomBytes(4).toString("hex");
    const alice = createIdentity({
      userId: `device-alice-${suffix}`,
      username: `devicealice${suffix}`,
      displayName: "Device Alice",
    });
    const bob = createIdentity({
      userId: `device-bob-${suffix}`,
      username: `devicebob${suffix}`,
      displayName: "Device Bob",
    });
    const deviceOne = createDevice("MacBook Pro");
    const deviceTwo = createDevice("Pixel 9 Pro");

    const registerOne = await request("/api/register", {
      method: "POST",
      headers: { "X-Notrus-Device-Id": deviceOne.descriptor.id },
      body: { ...alice.payload, device: deviceOne.descriptor },
    });
    if (registerOne.statusCode !== 200) {
      throw new Error(`Primary device registration failed with HTTP ${registerOne.statusCode}.`);
    }
    const sessionOne = registerOne.body?.session?.token;
    if (typeof sessionOne !== "string" || sessionOne.length < 20) {
      throw new Error("Primary device registration did not return a usable session token.");
    }

    const registerTwo = await request("/api/register", {
      method: "POST",
      headers: { "X-Notrus-Device-Id": deviceTwo.descriptor.id },
      body: { ...alice.payload, device: deviceTwo.descriptor },
    });
    if (registerTwo.statusCode !== 200) {
      throw new Error(`Secondary device registration failed with HTTP ${registerTwo.statusCode}.`);
    }
    const sessionTwo = registerTwo.body?.session?.token;
    if (typeof sessionTwo !== "string" || sessionTwo.length < 20) {
      throw new Error("Secondary device registration did not return a usable session token.");
    }

    const registerBob = await request("/api/register", {
      method: "POST",
      body: bob.payload,
    });
    if (registerBob.statusCode !== 200) {
      throw new Error(`Peer registration failed with HTTP ${registerBob.statusCode}.`);
    }

    const threadId = `device-thread-${suffix}`;
    const threadResponse = await request("/api/threads", {
      method: "POST",
      body: {
        createdAt: isoNow(),
        createdBy: alice.payload.userId,
        envelopes: [],
        groupState: null,
        id: threadId,
        initialRatchetPublicJwk: null,
        mlsBootstrap: null,
        participantIds: [alice.payload.userId, bob.payload.userId],
        protocol: "signal-pqxdh-double-ratchet-v1",
        title: "Device isolation",
      },
    });
    if (threadResponse.statusCode !== 201) {
      throw new Error(`Thread creation failed with HTTP ${threadResponse.statusCode}.`);
    }

    const securityDevices = await request("/api/security/devices", {
      headers: { Authorization: `Bearer ${sessionOne}` },
    });
    if (securityDevices.statusCode !== 200) {
      throw new Error(`Security devices snapshot failed with HTTP ${securityDevices.statusCode}.`);
    }
    if ((securityDevices.body.devices ?? []).length !== 2) {
      throw new Error(`Expected 2 linked devices, found ${(securityDevices.body.devices ?? []).length}.`);
    }

    const syncOne = await request("/api/sync/state", {
      headers: { Authorization: `Bearer ${sessionOne}` },
    });
    if (syncOne.statusCode !== 200) {
      throw new Error(`Device-one sync failed with HTTP ${syncOne.statusCode}.`);
    }
    if ((syncOne.body.threads?.[0]?.participantIds ?? []).length !== 2) {
      throw new Error("Thread membership was conflated with linked-device membership.");
    }

    const createdAt = isoNow();
    const payload = JSON.stringify({
      action: "device-revoke",
      createdAt,
      signerDeviceId: deviceOne.descriptor.id,
      targetDeviceId: deviceTwo.descriptor.id,
      userId: alice.payload.userId,
    });
    const signature = signPayload(deviceOne.privateKey, payload);
    const revoke = await request("/api/devices/revoke", {
      method: "POST",
      headers: { "X-Notrus-Device-Id": deviceOne.descriptor.id },
      body: {
        createdAt,
        signature,
        signerDeviceId: deviceOne.descriptor.id,
        targetDeviceId: deviceTwo.descriptor.id,
        userId: alice.payload.userId,
      },
    });
    if (revoke.statusCode !== 200) {
      throw new Error(`Device revoke failed with HTTP ${revoke.statusCode}.`);
    }

    const revokedDevices = await request("/api/security/devices", {
      headers: { Authorization: `Bearer ${sessionTwo}` },
    });
    if (!isAccessDenied(revokedDevices.statusCode)) {
      throw new Error(`Revoked device should be denied security-devices with HTTP 401/403, got ${revokedDevices.statusCode}.`);
    }

    const revokedSync = await request("/api/sync/state", {
      headers: { Authorization: `Bearer ${sessionTwo}` },
    });
    if (!isAccessDenied(revokedSync.statusCode)) {
      throw new Error(`Revoked device should be denied sync with HTTP 401/403, got ${revokedSync.statusCode}.`);
    }

    console.log("device-membership: linked devices stayed separate from thread membership, revocation required a device signature, and revoked devices lost sync access");
  } finally {
    if (managedRelay) {
      await stopRelay();
    }
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
