import { generateKeyPairSync, randomBytes, webcrypto } from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import http from "node:http";
import https from "node:https";

const rootDir = fileURLToPath(new URL("..", import.meta.url));
const relayOrigin = process.env.NOTRUS_ABUSE_RELAY_ORIGIN ?? "http://127.0.0.1:3012";
const relayUrl = new URL(relayOrigin);
const relayPort = Number(relayUrl.port || 3012);
const managedRelay = !process.env.NOTRUS_ABUSE_RELAY_ORIGIN;
let relayProcess = null;

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

function lowRiskIntegrityHeader() {
  return Buffer.from(
    JSON.stringify({
      bundleIdentifier: "com.notrus.android",
      codeSignatureStatus: "valid",
      deviceCheckStatus: "keystore-attestation-ready",
      deviceCheckTokenPresented: false,
      generatedAt: isoNow(),
      riskLevel: "low",
    }),
    "utf8"
  ).toString("base64");
}

function highRiskIntegrityHeader() {
  return Buffer.from(
    JSON.stringify({
      bundleIdentifier: "com.notrus.android.debug",
      codeSignatureStatus: "debuggable",
      deviceCheckStatus: "emulator",
      deviceCheckTokenPresented: false,
      generatedAt: isoNow(),
      riskLevel: "high",
    }),
    "utf8"
  ).toString("base64");
}

function leadingZeroBits(buffer) {
  let count = 0;
  for (const byte of buffer) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    for (let shift = 7; shift >= 0; shift -= 1) {
      if ((byte & (1 << shift)) === 0) {
        count += 1;
      } else {
        return count;
      }
    }
  }
  return count;
}

async function solvePowChallenge(challenge) {
  for (let counter = 0; counter < 50_000_000; counter += 1) {
    const nonce = counter.toString(16);
    const digest = await webcrypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(`${challenge.token}:${nonce}`)
    );
    if (leadingZeroBits(new Uint8Array(digest)) >= challenge.difficultyBits) {
      return nonce;
    }
  }
  throw new Error("Unable to solve the relay proof-of-work challenge.");
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

async function requestWithPow(pathname, options = {}) {
  const initial = await request(pathname, options);
  if (initial.statusCode !== 428) {
    return initial;
  }

  const challenge = initial.body.powChallenge;
  if (!challenge) {
    throw new Error(`${pathname} requested proof-of-work without a challenge payload.`);
  }

  const nonce = await solvePowChallenge(challenge);
  return request(pathname, {
    ...options,
    headers: {
      ...(options.headers ?? {}),
      [challenge.nonceField ?? "X-Notrus-Pow-Nonce"]: nonce,
      [challenge.tokenField ?? "X-Notrus-Pow-Token"]: challenge.token,
    },
  });
}

async function waitForHealth() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await request("/api/health");
      if (response.statusCode === 200) {
        return;
      }
    } catch {
      // keep waiting
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Timed out waiting for the abuse-controls relay.");
}

async function startRelay() {
  relayProcess = spawn(process.execPath, ["server.js"], {
    cwd: rootDir,
    env: {
      ...process.env,
      PORT: String(relayPort),
      TRUST_PROXY: "true",
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
    const remoteHeaders = {
      "X-Forwarded-For": "198.51.100.24",
    };
    const alice = identityPayload({
      userId: `abuse-alice-${suffix}`,
      username: `abusealice${suffix}`,
      displayName: "Abuse Alice",
    });
    const bob = identityPayload({
      userId: `abuse-bob-${suffix}`,
      username: `abusebob${suffix}`,
      displayName: "Abuse Bob",
    });

    const challengeRequired = await request("/api/register", {
      method: "POST",
      headers: remoteHeaders,
      body: alice,
    });
    if (challengeRequired.statusCode !== 428) {
      throw new Error(`Remote anonymous register should require proof-of-work, got HTTP ${challengeRequired.statusCode}.`);
    }

    const challengedRegister = await requestWithPow("/api/register", {
      method: "POST",
      headers: remoteHeaders,
      body: alice,
    });
    if (challengedRegister.statusCode !== 200) {
      throw new Error(`Remote challenged register failed with HTTP ${challengedRegister.statusCode}.`);
    }

    const lowRiskRegister = await request("/api/register", {
      method: "POST",
      headers: {
        ...remoteHeaders,
        "X-Notrus-Instance-Id": `android-instance-${suffix}`,
        "X-Notrus-Integrity": lowRiskIntegrityHeader(),
      },
      body: bob,
    });
    if (lowRiskRegister.statusCode !== 200) {
      throw new Error(`Low-risk native register should bypass proof-of-work, got HTTP ${lowRiskRegister.statusCode}.`);
    }

    const highRiskRegister = await request("/api/register", {
      method: "POST",
      headers: {
        ...remoteHeaders,
        "X-Notrus-Instance-Id": `android-debug-instance-${suffix}`,
        "X-Notrus-Integrity": highRiskIntegrityHeader(),
      },
      body: identityPayload({
        userId: `abuse-high-${suffix}`,
        username: `abusehigh${suffix}`,
        displayName: "Abuse High",
      }),
    });
    if (highRiskRegister.statusCode !== 428) {
      throw new Error(`High-risk native register should still require proof-of-work, got HTTP ${highRiskRegister.statusCode}.`);
    }

    const lookupChallenge = await request(
      `/api/directory/search?userId=${alice.userId}&q=${encodeURIComponent(lowRiskRegister.body.user.directoryCode)}`,
      {
        method: "GET",
        headers: remoteHeaders,
      }
    );
    if (lookupChallenge.statusCode !== 428) {
      throw new Error(`Remote directory lookup should require proof-of-work, got HTTP ${lookupChallenge.statusCode}.`);
    }

    const lookupResponse = await requestWithPow(
      `/api/directory/search?userId=${alice.userId}&q=${encodeURIComponent(lowRiskRegister.body.user.directoryCode)}`,
      {
        method: "GET",
        headers: remoteHeaders,
      }
    );
    if (lookupResponse.statusCode !== 200 || !lookupResponse.body.results?.some((entry) => entry.id === bob.userId)) {
      throw new Error("Proof-of-work directory lookup did not resolve the expected contact.");
    }

    const threadResponse = await requestWithPow("/api/threads", {
      method: "POST",
      headers: remoteHeaders,
      body: {
        createdAt: isoNow(),
        createdBy: alice.userId,
        envelopes: [],
        groupState: null,
        id: `abuse-thread-${suffix}`,
        initialRatchetPublicJwk: null,
        mlsBootstrap: null,
        participantIds: [alice.userId, bob.userId],
        protocol: "signal-pqxdh-double-ratchet-v1",
        title: "",
      },
    });
    if (threadResponse.statusCode !== 200 && threadResponse.statusCode !== 201) {
      throw new Error(`Remote thread creation with proof-of-work failed with HTTP ${threadResponse.statusCode}.`);
    }

    const reportChallenge = await request("/api/reports", {
      method: "POST",
      headers: remoteHeaders,
      body: {
        createdAt: isoNow(),
        messageIds: ["message-1"],
        reason: "abuse-or-spam",
        reporterId: alice.userId,
        targetUserId: bob.userId,
        threadId: `abuse-thread-${suffix}`,
      },
    });
    if (reportChallenge.statusCode !== 428) {
      throw new Error(`Remote abuse report should require proof-of-work, got HTTP ${reportChallenge.statusCode}.`);
    }

    const reportResponse = await requestWithPow("/api/reports", {
      method: "POST",
      headers: remoteHeaders,
      body: {
        createdAt: isoNow(),
        messageIds: ["message-1"],
        reason: "abuse-or-spam",
        reporterId: alice.userId,
        targetUserId: bob.userId,
        threadId: `abuse-thread-${suffix}`,
      },
    });
    if (reportResponse.statusCode !== 200) {
      throw new Error(`Remote abuse report with proof-of-work failed with HTTP ${reportResponse.statusCode}.`);
    }

    console.log("abuse-controls: remote anonymous register, lookup, thread creation, and report paths required proof-of-work, high-risk clients stayed constrained, and low-risk native register bypassed it");
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
