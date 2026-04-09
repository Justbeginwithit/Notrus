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
          service: "android-attestation",
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/attestation/android/verify") {
        const payload = await readJsonBody(request);
        const result = await verifyAndroidAttestation(payload);
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
