import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign as signBuffer } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { startAttestationServer } from "../attestation.js";

const execFileAsync = promisify(execFile);

function isoNow() {
  return new Date().toISOString();
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

function identityPayload({ userId, username, displayName, device }) {
  return {
    createdAt: isoNow(),
    device,
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
        return response.body;
      }
    } catch {
      // retry
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for ${origin}${pathname}.`);
}

async function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
  });
}

async function generateAndroidAttestationFixture(tempDir, { deviceId, storageMode }) {
  const leafConfig = `
[req]
distinguished_name=req_distinguished_name
prompt=no
req_extensions=v3_req

[req_distinguished_name]
CN=Notrus Android Key

[v3_req]
basicConstraints=CA:FALSE
keyUsage=digitalSignature
1.3.6.1.4.1.11129.2.1.17=ASN1:UTF8String:android-attestation-test
`;

  const leafConfigPath = path.join(tempDir, "leaf.cnf");
  const rootKey = path.join(tempDir, "root-key.pem");
  const rootCert = path.join(tempDir, "root.pem");
  const leafKey = path.join(tempDir, "leaf-key.pem");
  const leafCsr = path.join(tempDir, "leaf.csr");
  const leafCert = path.join(tempDir, "leaf.pem");
  const leafDer = path.join(tempDir, "leaf.der");
  const rootDer = path.join(tempDir, "root.der");

  await fs.writeFile(leafConfigPath, leafConfig);
  await execFileAsync("openssl", ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", rootKey]);
  await execFileAsync("openssl", ["req", "-x509", "-new", "-key", rootKey, "-subj", "/CN=Notrus Test Root", "-out", rootCert, "-days", "1"]);
  await execFileAsync("openssl", ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", leafKey]);
  await execFileAsync("openssl", ["req", "-new", "-key", leafKey, "-config", leafConfigPath, "-out", leafCsr]);
  await execFileAsync("openssl", [
    "x509",
    "-req",
    "-in",
    leafCsr,
    "-CA",
    rootCert,
    "-CAkey",
    rootKey,
    "-CAcreateserial",
    "-out",
    leafCert,
    "-days",
    "1",
    "-extfile",
    leafConfigPath,
    "-extensions",
    "v3_req",
  ]);
  await execFileAsync("openssl", ["x509", "-in", leafCert, "-outform", "DER", "-out", leafDer]);
  await execFileAsync("openssl", ["x509", "-in", rootCert, "-outform", "DER", "-out", rootDer]);

  const privateKey = createPrivateKey(await fs.readFile(leafKey));
  const publicJwk = privateKey.export({ format: "jwk" });
  const normalizedPublicJwk = {
    crv: publicJwk.crv,
    kty: publicJwk.kty,
    x: publicJwk.x,
    y: publicJwk.y,
  };
  const keyFingerprint = createHash("sha256")
    .update(JSON.stringify(normalizedPublicJwk))
    .digest("hex");
  const proofPayload = JSON.stringify({
    createdAt: "2026-04-04T00:00:00.000Z",
    deviceId,
    generatedAt: "2026-04-04T00:00:10.000Z",
    keyFingerprint,
    keyRole: "device-management",
    platform: "android",
    publicJwk: normalizedPublicJwk,
    storageMode,
  });
  const signed = signBuffer("sha256", Buffer.from(proofPayload, "utf8"), privateKey).toString("base64");

  return {
    attestation: {
      certificateChain: [
        (await fs.readFile(leafDer)).toString("base64"),
        (await fs.readFile(rootDer)).toString("base64"),
      ],
      generatedAt: "2026-04-04T00:00:10.000Z",
      keyFingerprint,
      keyRole: "device-management",
      proofPayload,
      proofSignature: signed,
      publicJwk: normalizedPublicJwk,
    },
    publicJwk: normalizedPublicJwk,
  };
}

function buildIntegrityHeader(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

async function withRelay({
  attestationOrigin,
  environment,
  relayOrigin,
  relayPort,
  tempDir,
  testFn,
}) {
  const relay = spawn(process.execPath, ["server.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ...environment,
      NOTRUS_ATTESTATION_ORIGIN: attestationOrigin,
      NOTRUS_DATA_DIR: path.join(tempDir, `relay-data-${relayPort}`),
      NOTRUS_PROTOCOL_POLICY: "require-standards",
      HOST: "127.0.0.1",
      PORT: String(relayPort),
    },
    stdio: "ignore",
  });

  try {
    const health = await waitForHealth(relayOrigin, "/api/health");
    await testFn(health);
  } finally {
    if (!relay.killed) {
      relay.kill("SIGTERM");
    }
    await new Promise((resolve) => relay.once("exit", resolve));
  }
}

async function runAndroidKeyAttestationScenario({ attestationOrigin, relayOrigin, relayPort, tempDir }) {
  await withRelay({
    attestationOrigin,
    environment: {
      NOTRUS_REQUIRE_ANDROID_ATTESTATION: "true",
    },
    relayOrigin,
    relayPort,
    tempDir,
    testFn: async (health) => {
      if (health.attestation?.configured !== true || health.attestation?.required !== true) {
        throw new Error("Relay health did not advertise required Android key attestation.");
      }

      const validDeviceId = "android-device-valid";
      const validFixture = await generateAndroidAttestationFixture(tempDir, {
        deviceId: validDeviceId,
        storageMode: "strongbox-device-key",
      });
      const validRegistration = await request(relayOrigin, "/api/register", {
        method: "POST",
        body: identityPayload({
          userId: "attestation-user-valid",
          username: "attestationvalid",
          displayName: "Attestation Valid",
          device: {
            attestation: validFixture.attestation,
            createdAt: isoNow(),
            id: validDeviceId,
            label: "Pixel Test",
            platform: "android",
            publicJwk: validFixture.publicJwk,
            riskLevel: "low",
            storageMode: "strongbox-device-key",
          },
        }),
        headers: {
          "X-Notrus-Device-Id": validDeviceId,
        },
      });
      if (validRegistration.statusCode !== 200) {
        throw new Error(
          `Valid Android attestation registration failed with HTTP ${validRegistration.statusCode}: ${JSON.stringify(validRegistration.body)}`
        );
      }

      const invalidDeviceId = "android-device-invalid";
      const invalidFixture = await generateAndroidAttestationFixture(tempDir, {
        deviceId: invalidDeviceId,
        storageMode: "strongbox-device-key",
      });
      invalidFixture.attestation.proofSignature = `${invalidFixture.attestation.proofSignature.slice(0, -4)}AAAA`;
      const invalidRegistration = await request(relayOrigin, "/api/register", {
        method: "POST",
        body: identityPayload({
          userId: "attestation-user-invalid",
          username: "attestationinvalid",
          displayName: "Attestation Invalid",
          device: {
            attestation: invalidFixture.attestation,
            createdAt: isoNow(),
            id: invalidDeviceId,
            label: "Tampered Pixel Test",
            platform: "android",
            publicJwk: invalidFixture.publicJwk,
            riskLevel: "medium",
            storageMode: "strongbox-device-key",
          },
        }),
        headers: {
          "X-Notrus-Device-Id": invalidDeviceId,
        },
      });
      if (invalidRegistration.statusCode !== 403) {
        throw new Error(
          `Tampered Android attestation should be rejected, got HTTP ${invalidRegistration.statusCode}: ${JSON.stringify(invalidRegistration.body)}`
        );
      }
    },
  });
}

async function runAppleDeviceCheckScenario({ attestationOrigin, relayOrigin, relayPort, tempDir }) {
  await withRelay({
    attestationOrigin,
    environment: {
      NOTRUS_REQUIRE_APPLE_DEVICECHECK: "true",
    },
    relayOrigin,
    relayPort,
    tempDir,
    testFn: async (health) => {
      if (health.attestation?.appleDeviceCheckRequired !== true) {
        throw new Error("Relay health did not advertise required Apple DeviceCheck verification.");
      }

      const validDeviceId = "mac-device-valid";
      const validRegistration = await request(relayOrigin, "/api/register", {
        method: "POST",
        body: identityPayload({
          userId: "devicecheck-user-valid",
          username: "devicecheckvalid",
          displayName: "DeviceCheck Valid",
          device: {
            createdAt: isoNow(),
            id: validDeviceId,
            label: "Mac Test",
            platform: "macos",
            publicJwk: generateJwk(),
            riskLevel: "low",
            storageMode: "keychain-device-key",
          },
        }),
        headers: {
          "X-Notrus-Device-Id": validDeviceId,
          "X-Notrus-Integrity": buildIntegrityHeader({
            bundleIdentifier: "com.notrus.mac",
            codeSignatureStatus: "valid",
            deviceCheckStatus: "token-issued",
            deviceCheckToken: "mock-devicecheck-token-valid-1",
            deviceCheckTokenPresented: true,
            generatedAt: isoNow(),
            riskLevel: "low",
          }),
        },
      });
      if (validRegistration.statusCode !== 200) {
        throw new Error(
          `Valid Apple DeviceCheck registration failed with HTTP ${validRegistration.statusCode}: ${JSON.stringify(validRegistration.body)}`
        );
      }

      const invalidDeviceId = "mac-device-invalid";
      const invalidRegistration = await request(relayOrigin, "/api/register", {
        method: "POST",
        body: identityPayload({
          userId: "devicecheck-user-invalid",
          username: "devicecheckinvalid",
          displayName: "DeviceCheck Invalid",
          device: {
            createdAt: isoNow(),
            id: invalidDeviceId,
            label: "Mac Invalid Test",
            platform: "macos",
            publicJwk: generateJwk(),
            riskLevel: "medium",
            storageMode: "keychain-device-key",
          },
        }),
        headers: {
          "X-Notrus-Device-Id": invalidDeviceId,
          "X-Notrus-Integrity": buildIntegrityHeader({
            bundleIdentifier: "com.notrus.mac",
            codeSignatureStatus: "valid",
            deviceCheckStatus: "token-issued",
            deviceCheckToken: "bad-token",
            deviceCheckTokenPresented: true,
            generatedAt: isoNow(),
            riskLevel: "low",
          }),
        },
      });
      if (invalidRegistration.statusCode !== 403) {
        throw new Error(
          `Invalid Apple DeviceCheck token should be rejected, got HTTP ${invalidRegistration.statusCode}: ${JSON.stringify(invalidRegistration.body)}`
        );
      }
    },
  });
}

async function runAndroidPlayIntegrityScenario({ attestationOrigin, relayOrigin, relayPort, tempDir }) {
  await withRelay({
    attestationOrigin,
    environment: {
      NOTRUS_REQUIRE_ANDROID_PLAY_INTEGRITY: "true",
    },
    relayOrigin,
    relayPort,
    tempDir,
    testFn: async (health) => {
      if (health.attestation?.androidPlayIntegrityRequired !== true) {
        throw new Error("Relay health did not advertise required Android Play Integrity verification.");
      }

      const validDeviceId = "android-play-valid";
      const validRegistration = await request(relayOrigin, "/api/register", {
        method: "POST",
        body: identityPayload({
          userId: "playintegrity-user-valid",
          username: "playintegrityvalid",
          displayName: "Play Integrity Valid",
          device: {
            createdAt: isoNow(),
            id: validDeviceId,
            label: "Android PI Test",
            platform: "android",
            publicJwk: generateJwk(),
            riskLevel: "low",
            storageMode: "strongbox-device-key",
          },
        }),
        headers: {
          "X-Notrus-Device-Id": validDeviceId,
          "X-Notrus-Integrity": buildIntegrityHeader({
            bundleIdentifier: "com.notrus.android",
            codeSignatureStatus: "valid",
            deviceCheckStatus: "keystore-attestation-ready",
            playIntegrityToken: "mock-play-integrity-token-valid-1",
            playIntegrityTokenPresented: true,
            generatedAt: isoNow(),
            riskLevel: "low",
          }),
        },
      });
      if (validRegistration.statusCode !== 200) {
        throw new Error(
          `Valid Play Integrity registration failed with HTTP ${validRegistration.statusCode}: ${JSON.stringify(validRegistration.body)}`
        );
      }

      const invalidDeviceId = "android-play-invalid";
      const invalidRegistration = await request(relayOrigin, "/api/register", {
        method: "POST",
        body: identityPayload({
          userId: "playintegrity-user-invalid",
          username: "playintegrityinvalid",
          displayName: "Play Integrity Invalid",
          device: {
            createdAt: isoNow(),
            id: invalidDeviceId,
            label: "Android PI Invalid",
            platform: "android",
            publicJwk: generateJwk(),
            riskLevel: "medium",
            storageMode: "strongbox-device-key",
          },
        }),
        headers: {
          "X-Notrus-Device-Id": invalidDeviceId,
          "X-Notrus-Integrity": buildIntegrityHeader({
            bundleIdentifier: "com.notrus.android",
            codeSignatureStatus: "valid",
            deviceCheckStatus: "keystore-attestation-ready",
            playIntegrityToken: "bad-token",
            playIntegrityTokenPresented: true,
            generatedAt: isoNow(),
            riskLevel: "medium",
          }),
        },
      });
      if (invalidRegistration.statusCode !== 403) {
        throw new Error(
          `Invalid Play Integrity token should be rejected, got HTTP ${invalidRegistration.statusCode}: ${JSON.stringify(invalidRegistration.body)}`
        );
      }
    },
  });
}

async function main() {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "notrus-attestation-enforcement-"));
  const attestationPort = await reservePort();
  const androidKeyPort = await reservePort();
  const appleDeviceCheckPort = await reservePort();
  const androidPlayIntegrityPort = await reservePort();
  const attestationOrigin = `http://127.0.0.1:${attestationPort}`;
  const attestationServer = startAttestationServer({ host: "127.0.0.1", port: attestationPort });

  try {
    await waitForHealth(attestationOrigin, "/api/attestation/health");

    await runAndroidKeyAttestationScenario({
      attestationOrigin,
      relayOrigin: `http://127.0.0.1:${androidKeyPort}`,
      relayPort: androidKeyPort,
      tempDir,
    });
    await runAppleDeviceCheckScenario({
      attestationOrigin,
      relayOrigin: `http://127.0.0.1:${appleDeviceCheckPort}`,
      relayPort: appleDeviceCheckPort,
      tempDir,
    });
    await runAndroidPlayIntegrityScenario({
      attestationOrigin,
      relayOrigin: `http://127.0.0.1:${androidPlayIntegrityPort}`,
      relayPort: androidPlayIntegrityPort,
      tempDir,
    });

    console.log(
      "attestation-enforcement: relay enforcement passed for Android key attestation, Apple DeviceCheck, and Android Play Integrity token verification"
    );
  } finally {
    await new Promise((resolve) => attestationServer.close(resolve));
    await fs.rm(tempDir, { force: true, recursive: true }).catch(() => {});
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
