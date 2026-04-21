import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import net from "node:net";
import { withManagedRelay } from "./managed-relay.mjs";

function isoNow() {
  return new Date().toISOString();
}

function randomBase64(bytes = 32) {
  return randomBytes(bytes).toString("base64");
}

function expectStatus(label, response, expected) {
  if (!expected.includes(response.statusCode)) {
    const details = typeof response.body === "string" ? response.body : JSON.stringify(response.body);
    throw new Error(`${label} returned HTTP ${response.statusCode}, expected ${expected.join("/")} (${details}).`);
  }
}

function ensure(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function normalizePublicJwk(jwk) {
  return {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };
}

function generatePublicJwk() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  return normalizePublicJwk(jwk);
}

function generateEcKeyMaterial() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  return {
    privateKey,
    publicJwk: normalizePublicJwk(jwk),
  };
}

function fakeSignalBundle() {
  return {
    deviceId: 1,
    identityKey: randomBase64(),
    kyberPreKeyId: 1,
    kyberPreKeyPublic: randomBase64(),
    kyberPreKeySignature: randomBase64(),
    preKeyId: 1,
    preKeyPublic: randomBase64(),
    registrationId: (randomBytes(2).readUInt16BE(0) % 32767) + 1,
    signedPreKeyId: 1,
    signedPreKeyPublic: randomBase64(),
    signedPreKeySignature: randomBase64(),
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

function createIdentity({ userId, username, displayName, recoveryFingerprint, recoveryPublicJwk }) {
  return {
    createdAt: isoNow(),
    displayName,
    encryptionPublicJwk: generatePublicJwk(),
    fingerprint: randomBytes(16).toString("hex"),
    mlsKeyPackage: null,
    prekeyCreatedAt: isoNow(),
    prekeyFingerprint: randomBytes(16).toString("hex"),
    prekeyPublicJwk: generatePublicJwk(),
    prekeySignature: randomBase64(64),
    recoveryFingerprint,
    recoveryPublicJwk,
    signalBundle: fakeSignalBundle(),
    signingPublicJwk: generatePublicJwk(),
    userId,
    username,
  };
}

function canonicalJwk(jwk) {
  return JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
}

function canonicalSignalBundle(bundle) {
  return JSON.stringify({
    deviceId: bundle.deviceId,
    identityKey: bundle.identityKey,
    kyberPreKeyId: bundle.kyberPreKeyId,
    kyberPreKeyPublic: bundle.kyberPreKeyPublic,
    kyberPreKeySignature: bundle.kyberPreKeySignature,
    preKeyId: bundle.preKeyId,
    preKeyPublic: bundle.preKeyPublic,
    registrationId: bundle.registrationId,
    signedPreKeyId: bundle.signedPreKeyId,
    signedPreKeyPublic: bundle.signedPreKeyPublic,
    signedPreKeySignature: bundle.signedPreKeySignature,
  });
}

function accountResetSignaturePayload(body) {
  return `{"createdAt":${JSON.stringify(body.createdAt)},"displayName":${JSON.stringify(body.displayName)},"encryption":${canonicalJwk(
    body.encryptionPublicJwk
  )},"fingerprint":${JSON.stringify(body.fingerprint)},"mlsKeyPackage":${
    body.mlsKeyPackage ? JSON.stringify(body.mlsKeyPackage.keyPackage) : "null"
  },"prekeyCreatedAt":${JSON.stringify(body.prekeyCreatedAt)},"prekeyFingerprint":${JSON.stringify(
    body.prekeyFingerprint
  )},"prekeyPublicJwk":${canonicalJwk(body.prekeyPublicJwk)},"prekeySignature":${JSON.stringify(
    body.prekeySignature
  )},"recoveryFingerprint":${JSON.stringify(body.recoveryFingerprint)},"recoveryPublicJwk":${canonicalJwk(
    body.recoveryPublicJwk
  )},"signalBundle":${body.signalBundle ? canonicalSignalBundle(body.signalBundle) : "null"},"signing":${canonicalJwk(
    body.signingPublicJwk
  )},"userId":${JSON.stringify(body.userId)},"username":${JSON.stringify(body.username)}}`;
}

function signRecoveryPayload(privateKey, payload) {
  const signer = createSign("sha256");
  signer.update(payload);
  signer.end();
  return signer.sign(privateKey).toString("base64");
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

function solvePowChallenge(challenge) {
  const difficultyBits = Number(challenge?.difficultyBits ?? 0);
  const token = typeof challenge?.token === "string" ? challenge.token : "";
  if (!token) {
    throw new Error("Relay returned an invalid proof-of-work challenge.");
  }

  for (let counter = 0; counter < 60_000_000; counter += 1) {
    const nonce = counter.toString(16);
    const digest = createHash("sha256").update(`${token}:${nonce}`).digest();
    if (leadingZeroBits(digest) >= difficultyBits) {
      return nonce;
    }
  }
  throw new Error("Unable to solve proof-of-work challenge.");
}

async function request(origin, pathname, { method = "GET", token = null, headers = {}, body = null } = {}) {
  const response = await fetch(new URL(pathname, origin), {
    method,
    headers: {
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const raw = await response.text();
  let decoded = raw;
  try {
    decoded = raw ? JSON.parse(raw) : {};
  } catch {
    // keep raw text for non-json errors
  }
  return {
    body: decoded,
    statusCode: response.status,
  };
}

async function requestWithPow(origin, pathname, options = {}) {
  const initial = await request(origin, pathname, options);
  if (initial.statusCode !== 428 || typeof initial.body !== "object" || !initial.body?.powChallenge) {
    return initial;
  }
  const challenge = initial.body.powChallenge;
  const nonce = solvePowChallenge(challenge);
  return request(origin, pathname, {
    ...options,
    headers: {
      ...(options.headers ?? {}),
      [challenge.tokenField ?? "X-Notrus-Pow-Token"]: challenge.token,
      [challenge.nonceField ?? "X-Notrus-Pow-Nonce"]: nonce,
    },
  });
}

async function run({ origin }) {
  const suffix = randomBytes(4).toString("hex");
  const aliceUserId = `recovery-alice-${suffix}`;
  const aliceUsername = `recalice${suffix}`;
  const recoveryKey = generateEcKeyMaterial();
  const recoveryFingerprint = randomBytes(16).toString("hex");

  const aliceInitial = createIdentity({
    displayName: "Recovery Alice",
    recoveryFingerprint,
    recoveryPublicJwk: recoveryKey.publicJwk,
    userId: aliceUserId,
    username: aliceUsername,
  });

  const aliceDeviceOne = createDevice("Alice Mac");
  const aliceDeviceTwo = createDevice("Alice Android");

  const registerOne = await requestWithPow(origin, "/api/bootstrap/register", {
    body: {
      ...aliceInitial,
      device: aliceDeviceOne.descriptor,
    },
    method: "POST",
  });
  expectStatus("register alice device one", registerOne, [200]);
  const sessionOne = registerOne.body?.session?.token;
  ensure(typeof sessionOne === "string" && sessionOne.length > 8, "Alice device-one registration returned no session.");

  const registerTwo = await requestWithPow(origin, "/api/bootstrap/register", {
    body: {
      ...aliceInitial,
      device: aliceDeviceTwo.descriptor,
    },
    method: "POST",
  });
  expectStatus("register alice device two", registerTwo, [200]);
  const sessionTwo = registerTwo.body?.session?.token;
  ensure(typeof sessionTwo === "string" && sessionTwo.length > 8, "Alice device-two registration returned no session.");

  const aliceSecurityBefore = await request(origin, "/api/security/devices", { token: sessionOne });
  expectStatus("security snapshot before reset", aliceSecurityBefore, [200]);
  ensure(
    Array.isArray(aliceSecurityBefore.body?.devices) && aliceSecurityBefore.body.devices.length >= 2,
    "Expected at least two linked devices before reset."
  );

  const bob = createIdentity({
    displayName: "Recovery Bob",
    recoveryFingerprint: randomBytes(16).toString("hex"),
    recoveryPublicJwk: generatePublicJwk(),
    userId: `recovery-bob-${suffix}`,
    username: `recbob${suffix}`,
  });
  const registerBob = await requestWithPow(origin, "/api/bootstrap/register", {
    body: bob,
    method: "POST",
  });
  expectStatus("register bob", registerBob, [200]);

  const bobSearch = await request(origin, `/api/directory/search?q=${encodeURIComponent(bob.username)}`, {
    token: sessionOne,
  });
  expectStatus("search bob", bobSearch, [200]);
  const bobResult = bobSearch.body?.results?.find((candidate) => candidate.id === bob.userId);
  ensure(typeof bobResult?.contactHandle === "string", "Directory search did not return Bob's contact handle.");

  const createThread = await request(origin, "/api/routing/threads", {
    body: {
      createdAt: isoNow(),
      id: `recovery-thread-${suffix}`,
      participantHandles: [bobResult.contactHandle],
      protocol: "signal-pqxdh-double-ratchet-v1",
      title: "",
    },
    method: "POST",
    token: sessionOne,
  });
  expectStatus("create direct thread", createThread, [200, 201]);
  const createdThreadId = createThread.body?.threadId;
  ensure(typeof createdThreadId === "string", "Thread creation did not return a threadId.");

  const aliceRotated = createIdentity({
    displayName: "Recovery Alice Rotated",
    recoveryFingerprint,
    recoveryPublicJwk: recoveryKey.publicJwk,
    userId: aliceUserId,
    username: aliceUsername,
  });
  const resetDevice = createDevice("Alice Recovery Device");

  const unsignedReset = {
    createdAt: isoNow(),
    device: resetDevice.descriptor,
    displayName: aliceRotated.displayName,
    encryptionPublicJwk: aliceRotated.encryptionPublicJwk,
    fingerprint: aliceRotated.fingerprint,
    mlsKeyPackage: null,
    prekeyCreatedAt: aliceRotated.prekeyCreatedAt,
    prekeyFingerprint: aliceRotated.prekeyFingerprint,
    prekeyPublicJwk: aliceRotated.prekeyPublicJwk,
    prekeySignature: aliceRotated.prekeySignature,
    recoveryFingerprint: aliceRotated.recoveryFingerprint,
    recoveryPublicJwk: aliceRotated.recoveryPublicJwk,
    recoverySignature: "",
    signalBundle: aliceRotated.signalBundle,
    signingPublicJwk: aliceRotated.signingPublicJwk,
    userId: aliceUserId,
    username: aliceUsername,
  };

  const invalidReset = await request(origin, "/api/account-reset", {
    body: {
      ...unsignedReset,
      recoverySignature: randomBase64(64),
    },
    method: "POST",
  });
  expectStatus("invalid account reset signature", invalidReset, [403]);

  const resetSignature = signRecoveryPayload(recoveryKey.privateKey, accountResetSignaturePayload(unsignedReset));
  const validReset = await request(origin, "/api/account-reset", {
    body: {
      ...unsignedReset,
      recoverySignature: resetSignature,
    },
    method: "POST",
  });
  expectStatus("valid account reset", validReset, [200]);
  const resetSession = validReset.body?.session?.token;
  ensure(typeof resetSession === "string" && resetSession.length > 8, "Account reset did not return a fresh session.");

  const oldSyncOne = await request(origin, "/api/sync/state", { token: sessionOne });
  expectStatus("old session one invalidated", oldSyncOne, [401, 403]);
  const oldSyncTwo = await request(origin, "/api/sync/state", { token: sessionTwo });
  expectStatus("old session two invalidated", oldSyncTwo, [401, 403]);

  const postResetSync = await request(origin, "/api/sync/state", { token: resetSession });
  expectStatus("post-reset sync", postResetSync, [200]);
  ensure(
    Array.isArray(postResetSync.body?.threads) && postResetSync.body.threads.some((thread) => thread.id === createdThreadId),
    "Post-reset sync did not include the previously created thread."
  );

  const postResetDevices = await request(origin, "/api/security/devices", { token: resetSession });
  expectStatus("post-reset device snapshot", postResetDevices, [200]);
  const activeDevices = (postResetDevices.body?.devices ?? []).filter((device) => !device.revokedAt);
  ensure(activeDevices.length === 1, "Account reset should leave exactly one active linked device.");
  ensure(activeDevices[0]?.id === resetDevice.descriptor.id, "Reset session should be bound to the newly enrolled device.");

  const deleteAccount = await request(origin, "/api/account/delete", {
    method: "POST",
    token: resetSession,
  });
  expectStatus("delete account", deleteAccount, [200]);

  const replacementIdentity = createIdentity({
    displayName: "Recovery Alice Rebound",
    recoveryFingerprint: randomBytes(16).toString("hex"),
    recoveryPublicJwk: generatePublicJwk(),
    userId: `recovery-alice-rebound-${suffix}`,
    username: aliceUsername,
  });
  const reboundRegistration = await requestWithPow(origin, "/api/bootstrap/register", {
    body: replacementIdentity,
    method: "POST",
  });
  expectStatus("register rebound username", reboundRegistration, [200]);
  ensure(
    reboundRegistration.body?.user?.id === replacementIdentity.userId,
    "Username rebinding after account deletion did not issue the replacement user id."
  );

  console.log(
    "recovery-lifecycle: account-reset signatures were enforced, old sessions/devices were invalidated, sync continuity held, and username rebinding after delete succeeded"
  );
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

const recoveryRelayPort = process.env.NOTRUS_RECOVERY_RELAY_PORT
  ? Number(process.env.NOTRUS_RECOVERY_RELAY_PORT)
  : await reservePort();

await withManagedRelay(
  {
    envOriginName: "NOTRUS_RECOVERY_RELAY_ORIGIN",
    port: recoveryRelayPort,
    protocolPolicy: "require-standards",
  },
  run
);
