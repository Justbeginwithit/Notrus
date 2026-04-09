import { generateKeyPairSync, randomBytes } from "node:crypto";
import http from "node:http";
import https from "node:https";

const relayOrigin = process.env.NOTRUS_ADVERSARIAL_RELAY_ORIGIN ?? "http://127.0.0.1:3000";
const relayUrl = new URL(relayOrigin);

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

function request(pathname, { method = "GET", headers = {}, body = null } = {}) {
  const url = new URL(pathname, relayUrl);
  const client = url.protocol === "https:" ? https : http;
  const payload =
    typeof body === "string" || Buffer.isBuffer(body)
      ? Buffer.from(body)
      : body == null
        ? null
        : Buffer.from(JSON.stringify(body), "utf8");

  return new Promise((resolve, reject) => {
    const req = client.request(
      url,
      {
        method,
        headers: payload
          ? {
              "Content-Length": String(payload.length),
              "Content-Type": headers["Content-Type"] ?? "application/json",
              ...headers,
            }
          : headers,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let decoded = raw;
          try {
            decoded = raw ? JSON.parse(raw) : {};
          } catch {
            decoded = raw;
          }
          resolve({
            body: decoded,
            statusCode: response.statusCode ?? 0,
          });
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

function expectStatus(label, actual, expectedStatuses) {
  if (!expectedStatuses.includes(actual.statusCode)) {
    throw new Error(`${label} returned HTTP ${actual.statusCode}, expected one of ${expectedStatuses.join(", ")}.`);
  }
}

async function main() {
  const suffix = randomBytes(4).toString("hex");
  const alice = identityPayload({
    userId: `adversarial-alice-${suffix}`,
    username: `advalice${suffix}`,
    displayName: "Adversarial Alice",
  });
  const bob = identityPayload({
    userId: `adversarial-bob-${suffix}`,
    username: `advbob${suffix}`,
    displayName: "Adversarial Bob",
  });
  const threadId = `adversarial-thread-${suffix}`;

  expectStatus("register alice", await request("/api/register", { method: "POST", body: alice }), [200]);
  expectStatus("register bob", await request("/api/register", { method: "POST", body: bob }), [200]);

  expectStatus(
    "malformed json",
    await request("/api/register", {
      method: "POST",
      body: "{\"displayName\":",
      headers: { "Content-Type": "application/json" },
    }),
    [400]
  );

  expectStatus(
    "wrong-type register",
    await request("/api/register", {
      method: "POST",
      body: { userId: 42, username: ["bad"], displayName: true },
    }),
    [400, 429]
  );

  expectStatus(
    "invalid thread create",
    await request("/api/threads", {
      method: "POST",
      body: {
        createdAt: isoNow(),
        createdBy: alice.userId,
        envelopes: [],
        id: threadId,
        participantIds: [alice.userId],
        protocol: "signal-pqxdh-double-ratchet-v1",
        title: "",
      },
    }),
    [400]
  );

  expectStatus(
    "valid thread create",
    await request("/api/threads", {
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
    }),
    [200, 201]
  );

  expectStatus(
    "invalid attachment",
    await request(`/api/threads/${threadId}/attachments`, {
      method: "POST",
      body: {
        byteLength: -1,
        ciphertext: "x",
        createdAt: isoNow(),
        id: `attachment-${suffix}`,
        iv: "bad",
        senderId: alice.userId,
        sha256: "bad",
        threadId,
      },
    }),
    [400]
  );

  expectStatus(
    "invalid report target thread mismatch",
    await request("/api/reports", {
      method: "POST",
      body: {
        createdAt: isoNow(),
        messageIds: ["message-1"],
        reason: "abuse-or-spam",
        reporterId: alice.userId,
        targetUserId: bob.userId,
        threadId: "non-existent-thread",
      },
    }),
    [404]
  );

  expectStatus(
    "valid minimal report",
    await request("/api/reports", {
      method: "POST",
      body: {
        createdAt: isoNow(),
        messageIds: ["message-1", "message-2"],
        reason: "abuse-or-spam",
        reporterId: alice.userId,
        targetUserId: bob.userId,
        threadId,
      },
    }),
    [200]
  );

  for (let index = 0; index < 25; index += 1) {
    const mutated = Buffer.from(randomBytes(24)).toString("base64");
    const response = await request("/api/reports", {
      method: "POST",
      body: {
        createdAt: index % 2 === 0 ? isoNow() : mutated,
        messageIds: Array.from({ length: 4 }, () => mutated),
        reason: index % 3 === 0 ? "abuse-or-spam" : mutated,
        reporterId: index % 4 === 0 ? alice.userId : mutated,
        targetUserId: bob.userId,
        threadId: index % 5 === 0 ? threadId : mutated,
      },
    });
    if (![200, 400, 404, 429].includes(response.statusCode)) {
      throw new Error(`mutated report ${index} returned unexpected HTTP ${response.statusCode}`);
    }
  }

  const health = await request("/api/health");
  expectStatus("health", health, [200]);
  if (!health.body?.ok) {
    throw new Error("relay health degraded after adversarial inputs");
  }

  console.log("adversarial-inputs: malformed and mutated relay requests stayed bounded without crashing the relay");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
