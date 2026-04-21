import { createHash, createPublicKey, generateKeyPairSync, randomBytes, verify as verifySignature } from "node:crypto";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";

function isoNow() {
  return new Date().toISOString();
}

function base64urlToBase64(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const remainder = normalized.length % 4;
  return remainder === 0 ? normalized : `${normalized}${"=".repeat(4 - remainder)}`;
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
    createdAt: isoNow(),
    displayName,
    encryptionPublicJwk: generateJwk(),
    fingerprint: createHash("sha256").update(randomBytes(16)).digest("hex").slice(0, 32),
    mlsKeyPackage: null,
    prekeyCreatedAt: isoNow(),
    prekeyFingerprint: createHash("sha256").update(randomBytes(16)).digest("hex").slice(0, 32),
    prekeyPublicJwk: generateJwk(),
    prekeySignature: randomBytes(64).toString("base64"),
    recoveryFingerprint: createHash("sha256").update(randomBytes(16)).digest("hex").slice(0, 32),
    recoveryPublicJwk: generateJwk(),
    signalBundle: fakeSignalBundle(),
    signingPublicJwk: generateJwk(),
    userId,
    username,
  };
}

function request(origin, pathname, { method = "GET", body = null, headers = {} } = {}) {
  const url = new URL(pathname, origin);
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

async function waitForHealth(origin, pathname = "/api/health") {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const response = await request(origin, pathname);
      if (response.statusCode === 200) {
        return;
      }
    } catch {
      // wait
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for ${origin}${pathname}.`);
}

function transparencyStatementPayload({ entryCount, signerKeyId, transparencyHead }) {
  return JSON.stringify({
    entryCount,
    signerKeyId,
    transparencyHead: transparencyHead ?? null,
  });
}

async function main() {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "notrus-key-directory-"));
  const relayPort = 3024;
  const witnessPort = 3424;
  const relayOrigin = `http://127.0.0.1:${relayPort}`;
  const witnessOrigin = `http://127.0.0.1:${witnessPort}`;

  const relay = spawn(process.execPath, ["server.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      NOTRUS_DATA_DIR: path.join(tempDir, "relay-data"),
      NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES: "true",
      NOTRUS_PROTOCOL_POLICY: "require-standards",
      PORT: String(relayPort),
    },
    stdio: "ignore",
  });

  let witnessServer = null;
  try {
    await waitForHealth(relayOrigin);

    process.env.WITNESS_DATA_DIR = path.join(tempDir, "witness-data");
    process.env.WITNESS_PORT = String(witnessPort);
    process.env.WITNESS_HOST = "127.0.0.1";
    process.env.RELAY_ORIGINS = relayOrigin;

    const witnessModule = await import("../witness.js");
    witnessServer = witnessModule.startWitnessServer({ host: "127.0.0.1", port: witnessPort });
    await waitForHealth(witnessOrigin, "/api/witness/health");

    const suffix = randomBytes(4).toString("hex");
    const alice = identityPayload({
      userId: `directory-alice-${suffix}`,
      username: `diralice${suffix}`,
      displayName: "Directory Alice",
    });
    const bob = identityPayload({
      userId: `directory-bob-${suffix}`,
      username: `dirbob${suffix}`,
      displayName: "Directory Bob",
    });

    const aliceRegister = await request(relayOrigin, "/api/register", { method: "POST", body: alice });
    const bobRegister = await request(relayOrigin, "/api/register", { method: "POST", body: bob });
    if (aliceRegister.statusCode !== 200 || bobRegister.statusCode !== 200) {
      throw new Error("Relay registration failed during key-directory proof.");
    }

    const sync = await request(relayOrigin, `/api/sync?userId=${alice.userId}`);
    if (sync.statusCode !== 200) {
      throw new Error(`Sync failed with HTTP ${sync.statusCode}.`);
    }
    const transparency = sync.body;
    if (!transparency.transparencySigner?.publicKeySpki || !transparency.transparencySignature) {
      throw new Error("Sync did not include a signed transparency statement.");
    }

    const signer = transparency.transparencySigner;
    const statement = transparencyStatementPayload({
      entryCount: transparency.entryCount,
      signerKeyId: signer.keyId,
      transparencyHead: transparency.transparencyHead,
    });
    const verified = verifySignature(
      null,
      Buffer.from(statement, "utf8"),
      createPublicKey({
        key: Buffer.from(signer.publicKeySpki, "base64"),
        format: "der",
        type: "spki",
      }),
      Buffer.from(transparency.transparencySignature, "base64")
    );
    if (!verified) {
      throw new Error("Relay transparency signature verification failed.");
    }

    const directoryCode = bobRegister.body.user.directoryCode;
    const lookup = await request(
      relayOrigin,
      `/api/directory/search?userId=${alice.userId}&q=${encodeURIComponent(directoryCode)}`,
    );
    if (lookup.statusCode !== 200 || !lookup.body.results?.some((user) => user.id === bob.userId)) {
      throw new Error("Explicit invite-code discovery failed during key-directory proof.");
    }

    await witnessModule.primeWitnesses();
    const witnessHead = await request(
      witnessOrigin,
      `/api/witness/head?relayOrigin=${encodeURIComponent(relayOrigin)}`,
    );
    const latest = witnessHead.body.latest;
    if (witnessHead.statusCode !== 200 || latest?.transparencyHead !== transparency.transparencyHead) {
      throw new Error("Witness did not converge on the relay transparency head.");
    }
    if (latest?.transparencySigner?.keyId !== signer.keyId) {
      throw new Error("Witness did not preserve the relay transparency signing identity.");
    }

    const transparencyDirect = await request(relayOrigin, "/api/transparency");
    if (transparencyDirect.statusCode !== 200 || transparencyDirect.body.transparencyHead !== transparency.transparencyHead) {
      throw new Error("Direct transparency endpoint diverged from sync.");
    }
    if (transparencyDirect.body.transparencySignature !== transparency.transparencySignature) {
      throw new Error("Sync and direct transparency signatures diverged.");
    }

    console.log("key-directory-transparency: relay head was signed, sync and transparency endpoints matched, invite-code discovery stayed explicit, and the witness observed the same signed head");
  } finally {
    witnessServer?.close();
    relay.kill("SIGTERM");
    await fs.rm(tempDir, { force: true, recursive: true }).catch(() => {});
    delete process.env.WITNESS_DATA_DIR;
    delete process.env.WITNESS_PORT;
    delete process.env.WITNESS_HOST;
    delete process.env.RELAY_ORIGINS;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
