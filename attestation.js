import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const PORT = Number(process.env.ATTESTATION_PORT || 3500);
const HOST = process.env.ATTESTATION_HOST || "127.0.0.1";
const ALLOW_ORIGINS = (process.env.ATTESTATION_ALLOW_ORIGINS ?? "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const APPLE_DEVICECHECK_MODE = (process.env.APPLE_DEVICECHECK_MODE ?? "mock").trim().toLowerCase();
const APPLE_DEVICECHECK_TEAM_ID = (process.env.APPLE_DEVICECHECK_TEAM_ID ?? "").trim();
const APPLE_DEVICECHECK_KEY_ID = (process.env.APPLE_DEVICECHECK_KEY_ID ?? "").trim();
const APPLE_DEVICECHECK_PRIVATE_KEY = (process.env.APPLE_DEVICECHECK_PRIVATE_KEY ?? "").trim();
const APPLE_DEVICECHECK_PRIVATE_KEY_PATH = (process.env.APPLE_DEVICECHECK_PRIVATE_KEY_PATH ?? "").trim();
const APPLE_DEVICECHECK_ENVIRONMENT = (process.env.APPLE_DEVICECHECK_ENVIRONMENT ?? "production").trim().toLowerCase();
const PLAY_INTEGRITY_MODE = (process.env.PLAY_INTEGRITY_MODE ?? "mock").trim().toLowerCase();
const PLAY_INTEGRITY_VERIFIER_ORIGIN = (process.env.PLAY_INTEGRITY_VERIFIER_ORIGIN ?? "").trim();

function setApiHeaders(request, response) {
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");

  const origin = request.headers.origin;
  if (ALLOW_ORIGINS.includes("*")) {
    response.setHeader("Access-Control-Allow-Origin", "*");
    return;
  }

  if (origin && ALLOW_ORIGINS.includes(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Vary", "Origin");
  }
}

function sendJson(request, response, statusCode, payload) {
  setApiHeaders(request, response);
  response.writeHead(statusCode);
  response.end(JSON.stringify(payload));
}

async function readJsonBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
    if (chunks.reduce((size, value) => size + value.length, 0) > 1_000_000) {
      throw new Error("Request body too large.");
    }
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
}

function isNonEmptyString(value, maxLength = 4_000) {
  return typeof value === "string" && value.trim().length > 0 && value.trim().length <= maxLength;
}

function normalizePublicJwk(jwk) {
  if (
    !jwk ||
    typeof jwk !== "object" ||
    !isNonEmptyString(jwk.x, 200) ||
    !isNonEmptyString(jwk.y, 200)
  ) {
    return null;
  }

  return {
    crv: isNonEmptyString(jwk.crv, 32) ? jwk.crv.trim() : "P-256",
    kty: isNonEmptyString(jwk.kty, 32) ? jwk.kty.trim() : "EC",
    x: jwk.x.trim(),
    y: jwk.y.trim(),
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

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function truthy(value) {
  return value === true;
}

async function readAppleDeviceCheckPrivateKey() {
  if (APPLE_DEVICECHECK_PRIVATE_KEY) {
    return APPLE_DEVICECHECK_PRIVATE_KEY;
  }
  if (APPLE_DEVICECHECK_PRIVATE_KEY_PATH) {
    return (await fs.readFile(APPLE_DEVICECHECK_PRIVATE_KEY_PATH, "utf8")).trim();
  }
  return "";
}

function decodeJsonPayload(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function toX509Chain(certificateChain) {
  if (!Array.isArray(certificateChain) || certificateChain.length === 0) {
    return [];
  }

  return certificateChain
    .filter((value) => isNonEmptyString(value, 16_000))
    .map((value) => new crypto.X509Certificate(Buffer.from(value.trim(), "base64")));
}

function verifyCertificateChain(certificates) {
  if (certificates.length === 0) {
    return { chainValid: false, rootFingerprint: null };
  }

  for (let index = 0; index < certificates.length - 1; index += 1) {
    const certificate = certificates[index];
    const issuer = certificates[index + 1];
    if (!certificate.checkIssued(issuer) || !certificate.verify(issuer.publicKey)) {
      return { chainValid: false, rootFingerprint: null };
    }
  }

  const root = certificates[certificates.length - 1];
  const rootFingerprint = sha256Hex(root.raw).slice(0, 32);
  return {
    chainValid: certificates.length > 1 ? root.verify(root.publicKey) : true,
    rootFingerprint,
  };
}

async function hasAndroidAttestationExtension(base64DerCertificate) {
  if (!isNonEmptyString(base64DerCertificate, 16_000)) {
    return false;
  }

  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "notrus-attestation-"));
  const certificatePath = path.join(directory, "leaf.der");

  try {
    await fs.writeFile(certificatePath, Buffer.from(base64DerCertificate.trim(), "base64"));
    const { stdout } = await execFileAsync("openssl", [
      "x509",
      "-inform",
      "DER",
      "-in",
      certificatePath,
      "-text",
      "-noout",
    ]);
    return stdout.includes("1.3.6.1.4.1.11129.2.1.17");
  } catch {
    return false;
  } finally {
    await fs.rm(directory, { force: true, recursive: true }).catch(() => {});
  }
}

function verifyProof(payload, signature, publicJwk) {
  if (!isNonEmptyString(payload, 8_000) || !isNonEmptyString(signature, 8_000) || !publicJwk) {
    return false;
  }

  try {
    const publicKey = crypto.createPublicKey({
      key: publicJwk,
      format: "jwk",
    });
    return crypto.verify(
      "sha256",
      Buffer.from(payload, "utf8"),
      publicKey,
      Buffer.from(signature.trim(), "base64")
    );
  } catch {
    return false;
  }
}

function publicJwkMatchesLeaf(publicJwk, leafCertificate) {
  if (!publicJwk || !leafCertificate) {
    return false;
  }

  try {
    const exported = leafCertificate.publicKey.export({ format: "jwk" });
    const normalizedLeaf = normalizePublicJwk(exported);
    return normalizedLeaf ? canonicalJwk(normalizedLeaf) === canonicalJwk(publicJwk) : false;
  } catch {
    return false;
  }
}

export async function verifyAndroidAttestation(payload) {
  const publicJwk = normalizePublicJwk(payload.publicJwk);
  const certificates = toX509Chain(payload.certificateChain);
  const leaf = certificates[0] ?? null;
  const chainResult = verifyCertificateChain(certificates);
  const proofValid = verifyProof(payload.proofPayload, payload.proofSignature, publicJwk);
  const keyMatches = publicJwkMatchesLeaf(publicJwk, leaf);
  const extensionPresent = await hasAndroidAttestationExtension(payload.certificateChain?.[0]);

  const verified = proofValid && keyMatches && chainResult.chainValid && extensionPresent;
  const status = verified
    ? "hardware-attested"
    : proofValid && keyMatches && chainResult.chainValid
      ? "chain-verified"
      : proofValid && keyMatches
        ? "proof-only"
        : "invalid";

  return {
    ok: true,
    platform: "android",
    status,
    verified,
    attestationExtensionPresent: extensionPresent,
    chainLength: certificates.length,
    chainValid: chainResult.chainValid,
    keyMatches,
    leafFingerprint: leaf ? sha256Hex(leaf.raw).slice(0, 32) : null,
    note:
      status === "hardware-attested"
        ? "Android key attestation chain, attestation extension, and proof-of-possession verified."
        : status === "chain-verified"
          ? "Certificate chain and proof-of-possession verified, but the Android attestation extension was not present."
          : status === "proof-only"
            ? "Proof-of-possession verified, but certificate-chain trust did not meet the Android attestation bar."
            : "Android attestation verification failed.",
    rootFingerprint: chainResult.rootFingerprint,
    verifiedAt: new Date().toISOString(),
  };
}

export async function verifyAppleDeviceCheck(payload) {
  const token = isNonEmptyString(payload?.deviceCheckToken, 16_000) ? payload.deviceCheckToken.trim() : null;
  const bundleIdentifier = isNonEmptyString(payload?.bundleIdentifier, 240) ? payload.bundleIdentifier.trim() : null;
  const transactionId = crypto.randomUUID();
  const timestampMs = Date.now();

  if (!token) {
    return {
      ok: true,
      platform: "apple",
      status: "missing-token",
      verified: false,
      note: "DeviceCheck verification failed because no device token was provided.",
      verifiedAt: new Date().toISOString(),
    };
  }

  if (APPLE_DEVICECHECK_MODE !== "live") {
    const verified = token.startsWith("mock-devicecheck-token-") || token.startsWith("mock-dc-");
    return {
      ok: true,
      platform: "apple",
      status: verified ? "devicecheck-mock-verified" : "devicecheck-mock-invalid",
      verified,
      note: verified
        ? "DeviceCheck token validated with the local mock verifier."
        : "DeviceCheck token was rejected by the local mock verifier.",
      verifiedAt: new Date().toISOString(),
    };
  }

  const privateKeyPem = await readAppleDeviceCheckPrivateKey();
  if (!APPLE_DEVICECHECK_TEAM_ID || !APPLE_DEVICECHECK_KEY_ID || !privateKeyPem) {
    return {
      ok: true,
      platform: "apple",
      status: "devicecheck-not-configured",
      verified: false,
      note: "Apple DeviceCheck live verification is not fully configured on this attestation service.",
      verifiedAt: new Date().toISOString(),
    };
  }

  try {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const jwtPayload = {
      aud: "devicecheck.apple.com",
      exp: nowSeconds + 300,
      iat: nowSeconds,
      iss: APPLE_DEVICECHECK_TEAM_ID,
      ...(bundleIdentifier ? { sub: bundleIdentifier } : {}),
    };

    const header = {
      alg: "ES256",
      kid: APPLE_DEVICECHECK_KEY_ID,
      typ: "JWT",
    };
    const encode = (value) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
    const unsignedJwt = `${encode(header)}.${encode(jwtPayload)}`;
    const signature = crypto.sign("sha256", Buffer.from(unsignedJwt, "utf8"), {
      key: privateKeyPem,
      dsaEncoding: "ieee-p1363",
    });
    const jwtToken = `${unsignedJwt}.${Buffer.from(signature).toString("base64url")}`;
    const endpoint =
      APPLE_DEVICECHECK_ENVIRONMENT === "development"
        ? "https://api.development.devicecheck.apple.com/v1/validate_device_token"
        : "https://api.devicecheck.apple.com/v1/validate_device_token";

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwtToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        device_token: token,
        timestamp: timestampMs,
        transaction_id: transactionId,
      }),
    });

    const raw = await response.text();
    const decoded = decodeJsonPayload(raw);
    const verified = response.ok;
    return {
      ok: true,
      platform: "apple",
      status: verified ? "devicecheck-verified" : "devicecheck-rejected",
      verified,
      note: verified
        ? "Apple DeviceCheck verification accepted the provided token."
        : `Apple DeviceCheck verification failed with HTTP ${response.status}.`,
      providerStatus: response.status,
      providerResponse: decoded,
      verifiedAt: new Date().toISOString(),
    };
  } catch {
    return {
      ok: true,
      platform: "apple",
      status: "devicecheck-error",
      verified: false,
      note: "Apple DeviceCheck verification request failed.",
      verifiedAt: new Date().toISOString(),
    };
  }
}

export async function verifyAndroidPlayIntegrity(payload) {
  const token = isNonEmptyString(payload?.playIntegrityToken, 16_000) ? payload.playIntegrityToken.trim() : null;
  if (!token) {
    return {
      ok: true,
      platform: "android",
      status: "missing-token",
      verified: false,
      note: "Play Integrity verification failed because no token was provided.",
      verifiedAt: new Date().toISOString(),
    };
  }

  if (PLAY_INTEGRITY_MODE !== "live") {
    const verified = token.startsWith("mock-play-integrity-token-") || token.startsWith("mock-play-");
    return {
      ok: true,
      platform: "android",
      status: verified ? "play-integrity-mock-verified" : "play-integrity-mock-invalid",
      verified,
      note: verified
        ? "Play Integrity token validated with the local mock verifier."
        : "Play Integrity token was rejected by the local mock verifier.",
      verifiedAt: new Date().toISOString(),
    };
  }

  if (!PLAY_INTEGRITY_VERIFIER_ORIGIN) {
    return {
      ok: true,
      platform: "android",
      status: "play-integrity-not-configured",
      verified: false,
      note: "Play Integrity live verification is not configured on this attestation service.",
      verifiedAt: new Date().toISOString(),
    };
  }

  try {
    const response = await fetch(new URL("/verify", PLAY_INTEGRITY_VERIFIER_ORIGIN), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const raw = await response.text();
    const decoded = decodeJsonPayload(raw) ?? {};
    const verified = response.ok && (truthy(decoded.verified) || truthy(decoded.tokenValid) || truthy(decoded.ok));
    return {
      ok: true,
      platform: "android",
      status: verified ? "play-integrity-verified" : "play-integrity-rejected",
      verified,
      note: verified
        ? "Play Integrity verifier accepted the provided token."
        : `Play Integrity verifier rejected the token with HTTP ${response.status}.`,
      providerStatus: response.status,
      providerResponse: decoded,
      verifiedAt: new Date().toISOString(),
    };
  } catch {
    return {
      ok: true,
      platform: "android",
      status: "play-integrity-error",
      verified: false,
      note: "Play Integrity verification request failed.",
      verifiedAt: new Date().toISOString(),
    };
  }
}

export function createAttestationServer() {
  return http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);

      if (request.method === "OPTIONS") {
        setApiHeaders(request, response);
        response.writeHead(204);
        response.end();
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/attestation/health") {
        sendJson(request, response, 200, {
          ok: true,
          capabilities: {
            androidKeyAttestation: true,
            appleDeviceCheck: true,
            playIntegrity: true,
          },
          mode: {
            appleDeviceCheck: APPLE_DEVICECHECK_MODE,
            playIntegrity: PLAY_INTEGRITY_MODE,
          },
          service: "notrus-attestation",
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/attestation/android/verify") {
        const payload = await readJsonBody(request);
        const result = await verifyAndroidAttestation(payload);
        sendJson(request, response, 200, result);
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/attestation/apple/devicecheck/verify") {
        const payload = await readJsonBody(request);
        const result = await verifyAppleDeviceCheck(payload);
        sendJson(request, response, 200, result);
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/attestation/android/play-integrity/verify") {
        const payload = await readJsonBody(request);
        const result = await verifyAndroidPlayIntegrity(payload);
        sendJson(request, response, 200, result);
        return;
      }

      sendJson(request, response, 404, { error: "Not found." });
    } catch (error) {
      console.error("Attestation request failed:", error);
      sendJson(request, response, 500, { error: "Attestation request failed." });
    }
  });
}

export function startAttestationServer({
  host = HOST,
  port = PORT,
} = {}) {
  const server = createAttestationServer();
  server.listen(port, host, () => {
    console.log(`Notrus Attestation listening on http://${host}:${port}`);
  });
  return server;
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file://").href) {
  startAttestationServer();
}
