import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, "..");
const storePath = path.join(root, "data", "store.json");

function reorderJwk(jwk) {
  if (!jwk) {
    return null;
  }

  return {
    y: jwk.y,
    x: jwk.x,
    kty: jwk.kty,
    crv: jwk.crv,
  };
}

const relayOrigin = process.argv[2] ?? "http://127.0.0.1:3001";
const requestedUserId = process.argv[3] ?? "";

const store = JSON.parse(await readFile(storePath, "utf8"));
const users = Object.values(store.users ?? {});
const user =
  users.find((candidate) => candidate.id === requestedUserId) ??
  users.find((candidate) => candidate.username === "tim") ??
  users.at(0);

if (!user) {
  throw new Error("No users found in data/store.json");
}

const payload = {
  userId: user.id,
  username: user.username,
  displayName: user.displayName,
  fingerprint: user.fingerprint,
  signingPublicJwk: reorderJwk(user.signingPublicJwk),
  encryptionPublicJwk: reorderJwk(user.encryptionPublicJwk),
  prekeyCreatedAt: user.prekeyCreatedAt,
  prekeyFingerprint: user.prekeyFingerprint,
  prekeyPublicJwk: reorderJwk(user.prekeyPublicJwk),
  prekeySignature: user.prekeySignature,
};

const response = await fetch(new URL("/api/register", relayOrigin), {
  method: "POST",
  headers: {
    "content-type": "application/json",
  },
  body: JSON.stringify(payload),
});

const text = await response.text();
console.log(JSON.stringify({
  ok: response.ok,
  status: response.status,
  bodyLength: text.length,
  bodyPreview: text.slice(0, 160),
  testedUserId: user.id,
  testedUsername: user.username,
}, null, 2));

if (!response.ok) {
  process.exitCode = 1;
}
