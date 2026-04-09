import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { verifyAndroidAttestation } from "../attestation.js";

const execFileAsync = promisify(execFile);
const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "notrus-attestation-test-"));

async function writeFile(name, content) {
  const filePath = path.join(tempDir, name);
  await fs.writeFile(filePath, content);
  return filePath;
}

async function generateFixture() {
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

  const leafConfigPath = await writeFile("leaf.cnf", leafConfig);
  const rootKey = path.join(tempDir, "root-key.pem");
  const rootCert = path.join(tempDir, "root.pem");
  const leafKey = path.join(tempDir, "leaf-key.pem");
  const leafCsr = path.join(tempDir, "leaf.csr");
  const leafCert = path.join(tempDir, "leaf.pem");
  const leafDer = path.join(tempDir, "leaf.der");
  const rootDer = path.join(tempDir, "root.der");

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

  const privateKey = crypto.createPrivateKey(await fs.readFile(leafKey));
  const publicJwk = privateKey.export({ format: "jwk" });
  const normalizedPublicJwk = {
    crv: publicJwk.crv,
    kty: publicJwk.kty,
    x: publicJwk.x,
    y: publicJwk.y,
  };
  const proofPayload = JSON.stringify({
    createdAt: "2026-04-04T00:00:00.000Z",
    deviceId: "android-device-1",
    generatedAt: "2026-04-04T00:00:10.000Z",
    keyFingerprint: crypto.createHash("sha256").update(JSON.stringify(normalizedPublicJwk)).digest("hex"),
    keyRole: "device-management",
    platform: "android",
    publicJwk: normalizedPublicJwk,
    storageMode: "strongbox-device-key",
  });
  const proofSignature = crypto.sign("sha256", Buffer.from(proofPayload, "utf8"), privateKey).toString("base64");

  return {
    certificateChain: [
      (await fs.readFile(leafDer)).toString("base64"),
      (await fs.readFile(rootDer)).toString("base64"),
    ],
    generatedAt: "2026-04-04T00:00:10.000Z",
    keyFingerprint: crypto.createHash("sha256").update(JSON.stringify(normalizedPublicJwk)).digest("hex"),
    keyRole: "device-management",
    proofPayload,
    proofSignature,
    publicJwk: normalizedPublicJwk,
  };
}

try {
  const payload = await generateFixture();
  const okResult = await verifyAndroidAttestation(payload);
  assert.equal(okResult.verified, true);
  assert.equal(okResult.status, "hardware-attested");

  const badResult = await verifyAndroidAttestation({
    ...payload,
    proofSignature: payload.proofSignature.slice(0, -4) + "AAAA",
  });
  assert.equal(badResult.verified, false);
  assert.equal(badResult.status, "invalid");

  console.log("Attestation service proofs passed.");
} finally {
  await fs.rm(tempDir, { force: true, recursive: true }).catch(() => {});
}
