import http from "node:http";
import https from "node:https";
import { promises as fs } from "node:fs";
import path from "node:path";
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as signPayload,
  verify as verifySignature,
} from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  getProtocolSpec,
  protocolAllowedUnderPolicy,
  protocolPolicySummary,
  resolveProtocolPolicy,
} from "./protocol-policy.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const env = (name) => process.env[name];
const DATA_DIR = env("NOTRUS_DATA_DIR")
  ? path.resolve(env("NOTRUS_DATA_DIR"))
  : path.join(__dirname, "data");
const SECRET_DIR = env("NOTRUS_SECRET_DIR")
  ? path.resolve(env("NOTRUS_SECRET_DIR"))
  : path.join(__dirname, ".secrets");
const STORE_PATH = env("NOTRUS_STORE_PATH")
  ? path.resolve(env("NOTRUS_STORE_PATH"))
  : path.join(DATA_DIR, "store.json");
const TRANSPARENCY_KEY_PATH = env("NOTRUS_TRANSPARENCY_KEY_PATH")
  ? path.resolve(env("NOTRUS_TRANSPARENCY_KEY_PATH"))
  : path.join(SECRET_DIR, "transparency-signing-key.json");
const LEGACY_TRANSPARENCY_KEY_PATH = path.join(DATA_DIR, "transparency-signing-key.json");
const PORT = Number(process.env.PORT || 3000);
const HTTPS_PORT = Number(process.env.HTTPS_PORT || PORT);
const HOST = process.env.HOST || "127.0.0.1";
const HTTPS_KEY_FILE = process.env.HTTPS_KEY_FILE ?? "";
const HTTPS_CERT_FILE = process.env.HTTPS_CERT_FILE ?? "";
const ATTESTATION_ORIGIN = env("NOTRUS_ATTESTATION_ORIGIN")?.trim() ?? "";
const REQUIRE_ANDROID_ATTESTATION = env("NOTRUS_REQUIRE_ANDROID_ATTESTATION") === "true";
const REQUIRE_ANDROID_PLAY_INTEGRITY = env("NOTRUS_REQUIRE_ANDROID_PLAY_INTEGRITY") === "true";
const REQUIRE_APPLE_DEVICECHECK = env("NOTRUS_REQUIRE_APPLE_DEVICECHECK") === "true";
const ENABLE_LEGACY_API_ROUTES = env("NOTRUS_ENABLE_LEGACY_API") === "true" || process.env.NODE_ENV !== "production";
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const CLIENT_ORIGINS = (process.env.CLIENT_ORIGIN ?? "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const MAX_THREAD_PARTICIPANTS = Number(process.env.MAX_THREAD_PARTICIPANTS || 32);
const ACTIVE_PROTOCOL_POLICY = resolveProtocolPolicy(env("NOTRUS_PROTOCOL_POLICY"));
const DIRECTORY_SEARCH_LIMIT = Number(process.env.DIRECTORY_SEARCH_LIMIT || 10);
const DIRECTORY_SEARCH_MIN_LENGTH = Number(process.env.DIRECTORY_SEARCH_MIN_LENGTH || 3);
const MESSAGE_RETENTION_MS = Number(process.env.MESSAGE_RETENTION_MS || 14 * 24 * 60 * 60 * 1000);
const ATTACHMENT_RETENTION_MS = Number(process.env.ATTACHMENT_RETENTION_MS || 14 * 24 * 60 * 60 * 1000);
const REPORT_RETENTION_MS = Number(process.env.REPORT_RETENTION_MS || 7 * 24 * 60 * 60 * 1000);
const DEVICE_EVENT_RETENTION_MS = Number(process.env.DEVICE_EVENT_RETENTION_MS || 30 * 24 * 60 * 60 * 1000);
const SESSION_TOKEN_TTL_MS = Number(process.env.SESSION_TOKEN_TTL_MS || 15 * 60 * 1000);
const CONTACT_HANDLE_TTL_MS = Number(process.env.CONTACT_HANDLE_TTL_MS || 10 * 60 * 1000);
const MAILBOX_HANDLE_TTL_MS = Number(process.env.MAILBOX_HANDLE_TTL_MS || 10 * 60 * 1000);
const MAILBOX_CAPABILITY_TTL_MS = Number(process.env.MAILBOX_CAPABILITY_TTL_MS || 10 * 60 * 1000);
const RATE_LIMIT_HMAC_KEY = process.env.RATE_LIMIT_HMAC_KEY || randomUUID();
const POW_HMAC_KEY = process.env.POW_HMAC_KEY || randomUUID();
const POW_DIFFICULTY_BITS = Number(process.env.POW_DIFFICULTY_BITS || 18);
const POW_EXPIRY_MS = Number(process.env.POW_EXPIRY_MS || 5 * 60 * 1000);
const RATE_LIMITS = {
  eventsPerIp: {
    limit: Number(process.env.RATE_EVENTS_PER_IP || 30),
    windowMs: Number(process.env.RATE_EVENTS_PER_IP_WINDOW_MS || 60_000),
  },
  messagePerIp: {
    limit: Number(process.env.RATE_MESSAGE_PER_IP || 240),
    windowMs: Number(process.env.RATE_MESSAGE_PER_IP_WINDOW_MS || 60_000),
  },
  messagePerUser: {
    limit: Number(process.env.RATE_MESSAGE_PER_USER || 120),
    windowMs: Number(process.env.RATE_MESSAGE_PER_USER_WINDOW_MS || 60_000),
  },
  registerPerIp: {
    limit: Number(process.env.RATE_REGISTER_PER_IP || 18),
    windowMs: Number(process.env.RATE_REGISTER_PER_IP_WINDOW_MS || 300_000),
  },
  registerPerInstance: {
    limit: Number(process.env.RATE_REGISTER_PER_INSTANCE || 12),
    windowMs: Number(process.env.RATE_REGISTER_PER_INSTANCE_WINDOW_MS || 300_000),
  },
  registerRefreshPerIp: {
    limit: Number(process.env.RATE_REGISTER_REFRESH_PER_IP || 120),
    windowMs: Number(process.env.RATE_REGISTER_REFRESH_PER_IP_WINDOW_MS || 60_000),
  },
  registerRefreshPerInstance: {
    limit: Number(process.env.RATE_REGISTER_REFRESH_PER_INSTANCE || 60),
    windowMs: Number(process.env.RATE_REGISTER_REFRESH_PER_INSTANCE_WINDOW_MS || 60_000),
  },
  reportPerUser: {
    limit: Number(process.env.RATE_REPORT_PER_USER || 20),
    windowMs: Number(process.env.RATE_REPORT_PER_USER_WINDOW_MS || 3_600_000),
  },
  searchPerInstance: {
    limit: Number(process.env.RATE_SEARCH_PER_INSTANCE || 20),
    windowMs: Number(process.env.RATE_SEARCH_PER_INSTANCE_WINDOW_MS || 60_000),
  },
  syncPerIp: {
    limit: Number(process.env.RATE_SYNC_PER_IP || 240),
    windowMs: Number(process.env.RATE_SYNC_PER_IP_WINDOW_MS || 60_000),
  },
  searchPerIp: {
    limit: Number(process.env.RATE_SEARCH_PER_IP || 30),
    windowMs: Number(process.env.RATE_SEARCH_PER_IP_WINDOW_MS || 60_000),
  },
  threadPerIp: {
    limit: Number(process.env.RATE_THREAD_PER_IP || 30),
    windowMs: Number(process.env.RATE_THREAD_PER_IP_WINDOW_MS || 600_000),
  },
  threadPerUser: {
    limit: Number(process.env.RATE_THREAD_PER_USER || 15),
    windowMs: Number(process.env.RATE_THREAD_PER_USER_WINDOW_MS || 600_000),
  },
};

const SSE_CLIENTS = new Map();
const RATE_LIMIT_BUCKETS = new Map();
const SESSION_CAPABILITIES = new Map();
const CONTACT_HANDLES = new Map();
const CONTACT_HANDLE_INDEX = new Map();
const MAILBOX_ROUTING = new Map();
const MAILBOX_CAPABILITIES = new Map();
const MAILBOX_CAPABILITY_INDEX = new Map();
const SNAKE_ASSETS = new Map([
  [
    "/snake",
    {
      contentSecurityPolicy: "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'self'; style-src 'self'",
      contentType: "text/html; charset=utf-8",
      filePath: path.join(__dirname, "snake", "index.html"),
    },
  ],
  [
    "/snake/",
    {
      contentSecurityPolicy: "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'self'; style-src 'self'",
      contentType: "text/html; charset=utf-8",
      filePath: path.join(__dirname, "snake", "index.html"),
    },
  ],
  [
    "/snake/app.js",
    {
      contentType: "text/javascript; charset=utf-8",
      filePath: path.join(__dirname, "snake", "app.js"),
    },
  ],
  [
    "/snake/game.js",
    {
      contentType: "text/javascript; charset=utf-8",
      filePath: path.join(__dirname, "snake", "game.js"),
    },
  ],
  [
    "/snake/styles.css",
    {
      contentType: "text/css; charset=utf-8",
      filePath: path.join(__dirname, "snake", "styles.css"),
    },
  ],
]);
let persistQueue = Promise.resolve();
let store = await loadStore();
const TRANSPARENCY_SIGNER = await loadOrCreateTransparencySigner();

if (store.wasNormalized) {
  delete store.wasNormalized;
  await saveStore();
}

function setSharedHeaders(response) {
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  if (HTTPS_KEY_FILE && HTTPS_CERT_FILE) {
    response.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
}

function setApiHeaders(request, response) {
  setSharedHeaders(response);
  response.setHeader(
    "Access-Control-Allow-Headers",
    "Authorization,Content-Type,X-Notrus-Capability,X-Notrus-Integrity,X-Notrus-Instance-Id,X-Notrus-Pow-Nonce,X-Notrus-Pow-Token,X-Notrus-Device-Id,X-Notrus-Session"
  );
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

  const origin = request.headers.origin;
  if (CLIENT_ORIGINS.includes("*")) {
    response.setHeader("Access-Control-Allow-Origin", "*");
    return;
  }

  if (origin && CLIENT_ORIGINS.includes(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Vary", "Origin");
  }
}

async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function ensureSecretDir() {
  await fs.mkdir(path.dirname(TRANSPARENCY_KEY_PATH), { recursive: true });
}

async function loadStore() {
  await ensureDataDir();

  try {
    const raw = await fs.readFile(STORE_PATH, "utf8");
    const parsed = JSON.parse(raw);
    const users = Object.fromEntries(
      Object.entries(parsed.users ?? {}).map(([userId, user]) => [userId, normalizeUserRecord(user)])
    );
    const reports = Array.isArray(parsed.reports) ? parsed.reports.map(normalizeAbuseReportRecord).filter(Boolean) : [];
    const threads = Object.fromEntries(
      Object.entries(parsed.threads ?? {}).map(([threadId, thread]) => [threadId, normalizeThreadRecord(thread)])
    );
    const normalizedTransparency = normalizeTransparencyLog(parsed.transparencyLog);
    return {
      reports,
      transparencyHead: normalizedTransparency.head,
      transparencyLog: normalizedTransparency.entries,
      users,
      threads,
      wasNormalized: normalizedTransparency.wasNormalized || parsed.transparencyHead !== normalizedTransparency.head,
    };
  } catch (error) {
    if (error.code === "ENOENT") {
      return { reports: [], transparencyHead: null, transparencyLog: [], users: {}, threads: {}, wasNormalized: false };
    }

    throw error;
  }
}

async function loadOrCreateTransparencySigner() {
  await ensureDataDir();
  await ensureSecretDir();

  const envPrivateKeyPem = env("NOTRUS_TRANSPARENCY_PRIVATE_KEY_PEM")?.trim();
  if (envPrivateKeyPem) {
    return transparencySignerFromPrivateKeyPem(envPrivateKeyPem);
  }

  const storedSigner = await readTransparencySignerRecord(TRANSPARENCY_KEY_PATH);
  if (storedSigner) {
    return transparencySignerFromRecord(storedSigner);
  }

  const legacySigner = await readTransparencySignerRecord(LEGACY_TRANSPARENCY_KEY_PATH);
  if (legacySigner) {
    const rotated = createTransparencySignerRecord();
    await writeTransparencySignerRecord(TRANSPARENCY_KEY_PATH, rotated.record);
    await scrubLegacyTransparencyKeyFile(legacySigner);
    return rotated.signer;
  }

  const created = createTransparencySignerRecord();
  await writeTransparencySignerRecord(TRANSPARENCY_KEY_PATH, created.record);
  return created.signer;
}

function createTransparencySignerRecord() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const signer = transparencySignerFromPrivateKeyPem(privateKeyPem);
  return {
    record: {
      keyId: signer.public.keyId,
      privateKeyPem,
      publicKeyRaw: signer.public.publicKeyRaw,
      publicKeySpki: signer.public.publicKeySpki,
    },
    signer,
  };
}

function transparencySignerFromPrivateKeyPem(privateKeyPem) {
  const privateKey = createPrivateKey(privateKeyPem);
  const publicKey = createPublicKey(privateKey);
  const publicKeySpki = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const publicJwk = publicKey.export({ format: "jwk" });
  const publicKeyRaw = base64urlDecode(publicJwk.x).toString("base64");
  const keyId = createHash("sha256").update(Buffer.from(publicKeySpki, "base64")).digest("hex").slice(0, 24);
  return {
    privateKey,
    public: {
      algorithm: "ed25519",
      keyId,
      publicKeyRaw,
      publicKeySpki,
    },
  };
}

function transparencySignerFromRecord(record) {
  return {
    privateKey: createPrivateKey(record.privateKeyPem),
    public: {
      algorithm: "ed25519",
      keyId: record.keyId,
      publicKeyRaw: record.publicKeyRaw,
      publicKeySpki: record.publicKeySpki,
    },
  };
}

async function readTransparencySignerRecord(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    if (
      isNonEmptyString(parsed.privateKeyPem, 16_000) &&
      isNonEmptyString(parsed.publicKeyRaw, 1_000) &&
      isNonEmptyString(parsed.publicKeySpki, 8_000) &&
      isNonEmptyString(parsed.keyId, 120)
    ) {
      return {
        keyId: parsed.keyId,
        privateKeyPem: parsed.privateKeyPem,
        publicKeyRaw: parsed.publicKeyRaw,
        publicKeySpki: parsed.publicKeySpki,
      };
    }
    return null;
  } catch (error) {
    if (error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

async function writeTransparencySignerRecord(filePath, record) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(record, null, 2), "utf8");
  await fs.chmod(filePath, 0o600).catch(() => {});
}

async function scrubLegacyTransparencyKeyFile(legacySigner) {
  const notice = {
    compromised: true,
    migratedAt: new Date().toISOString(),
    note: "The legacy repo-tracked transparency signer was rotated and removed from this file. The active private key now lives outside tracked source.",
    previousKeyId: legacySigner.keyId,
    publicKeyRaw: legacySigner.publicKeyRaw,
    publicKeySpki: legacySigner.publicKeySpki,
  };
  await fs.writeFile(LEGACY_TRANSPARENCY_KEY_PATH, JSON.stringify(notice, null, 2), "utf8");
}

function transparencyStatementPayload({ entryCount, transparencyHead, signerKeyId }) {
  return JSON.stringify({
    entryCount,
    signerKeyId,
    transparencyHead: transparencyHead ?? null,
  });
}

function signedTransparencyState() {
  const payload = transparencyStatementPayload({
    entryCount: store.transparencyLog.length,
    transparencyHead: store.transparencyHead,
    signerKeyId: TRANSPARENCY_SIGNER.public.keyId,
  });
  return {
    payload,
    signature: signPayload(null, Buffer.from(payload, "utf8"), TRANSPARENCY_SIGNER.privateKey).toString("base64"),
    signer: TRANSPARENCY_SIGNER.public,
  };
}

function queuePersist() {
  const snapshot = JSON.stringify(store, null, 2);
  persistQueue = persistQueue.then(() => fs.writeFile(STORE_PATH, snapshot, "utf8"));
  return persistQueue;
}

async function readJsonBody(request) {
  const chunks = [];
  let totalBytes = 0;

  for await (const chunk of request) {
    totalBytes += chunk.length;

    if (totalBytes > 1_000_000) {
      throw new Error("Request body exceeded the 1 MB limit.");
    }

    chunks.push(chunk);
  }

  if (chunks.length === 0) {
    return {};
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function getRequestIp(request) {
  if (TRUST_PROXY) {
    const forwarded = request.headers["x-forwarded-for"];
    if (typeof forwarded === "string" && forwarded.trim()) {
      return forwarded.split(",")[0].trim();
    }
  }

  return request.socket.remoteAddress ?? "unknown";
}

function privacyPreservingRateLimitKey(rawKey) {
  return createHmac("sha256", RATE_LIMIT_HMAC_KEY).update(String(rawKey)).digest("hex");
}

function privacyScopedBucketKey(scope, rawKey) {
  return privacyPreservingRateLimitKey(`${scope}:${String(rawKey)}`);
}

function getRequestInstanceKey(request) {
  const instanceId = request.headers["x-notrus-instance-id"];
  if (typeof instanceId !== "string" || !isNonEmptyString(instanceId, 200)) {
    return null;
  }
  return privacyPreservingRateLimitKey(instanceId.trim());
}

function nowIso() {
  return new Date().toISOString();
}

function opaqueToken(bytes = 24) {
  return base64urlEncode(randomBytes(bytes));
}

function sessionKeyForUser(userId, deviceId) {
  return `${userId}:${deviceId ?? "no-device"}`;
}

function pruneEphemeralPrivacyState() {
  const now = Date.now();

  for (const [token, session] of SESSION_CAPABILITIES.entries()) {
    if (!session || now >= session.expiresAtMs) {
      SESSION_CAPABILITIES.delete(token);
    }
  }

  for (const [handle, record] of CONTACT_HANDLES.entries()) {
    if (!record || now >= record.expiresAtMs) {
      CONTACT_HANDLES.delete(handle);
      CONTACT_HANDLE_INDEX.delete(`${record?.viewerUserId ?? ""}:${record?.targetUserId ?? ""}`);
    }
  }

  for (const [threadId, routing] of MAILBOX_ROUTING.entries()) {
    if (!routing || now >= routing.expiresAtMs) {
      MAILBOX_ROUTING.delete(threadId);
    }
  }

  for (const [token, record] of MAILBOX_CAPABILITIES.entries()) {
    if (!record || now >= record.expiresAtMs) {
      MAILBOX_CAPABILITIES.delete(token);
      MAILBOX_CAPABILITY_INDEX.delete(`${record?.threadId ?? ""}:${record?.userId ?? ""}`);
    }
  }
}

function issueSessionCapability({ userId, deviceId = null, integrityObservation = null }) {
  pruneEphemeralPrivacyState();
  const token = opaqueToken(24);
  const issuedAtMs = Date.now();
  const session = {
    deviceId,
    expiresAtMs: issuedAtMs + SESSION_TOKEN_TTL_MS,
    integrityRiskLevel: integrityObservation?.riskLevel ?? "unknown",
    issuedAtMs,
    kind: "session",
    sessionId: opaqueToken(12),
    token,
    userId,
  };
  SESSION_CAPABILITIES.set(token, session);
  return {
    expiresAt: new Date(session.expiresAtMs).toISOString(),
    privacyMode: "opaque-routing-v1",
    sessionId: session.sessionId,
    token,
  };
}

function readAuthorizationToken(request) {
  const authorization = request.headers.authorization;
  if (typeof authorization === "string" && authorization.startsWith("Bearer ")) {
    const token = authorization.slice("Bearer ".length).trim();
    if (isNonEmptyString(token, 4_096)) {
      return token;
    }
  }

  const legacySession = request.headers["x-notrus-session"];
  if (typeof legacySession === "string" && isNonEmptyString(legacySession, 4_096)) {
    return legacySession.trim();
  }

  const capability = request.headers["x-notrus-capability"];
  if (typeof capability === "string" && isNonEmptyString(capability, 4_096)) {
    return capability.trim();
  }

  return null;
}

function requireSessionCapability(request, response) {
  pruneEphemeralPrivacyState();
  const token = readAuthorizationToken(request);
  if (!token) {
    sendError(request, response, 401, "A current Notrus session token is required.");
    return null;
  }

  const session = SESSION_CAPABILITIES.get(token);
  if (!session || session.kind !== "session" || Date.now() >= session.expiresAtMs) {
    SESSION_CAPABILITIES.delete(token);
    sendError(request, response, 401, "The Notrus session token has expired. Bootstrap the relay session again.");
    return null;
  }

  const user = store.users[session.userId];
  if (!user || user.deactivatedAt) {
    SESSION_CAPABILITIES.delete(token);
    sendError(request, response, 401, "The current relay account is no longer active.");
    return null;
  }

  if (session.deviceId) {
    const device = findUserDevice(user, session.deviceId);
    if (!device) {
      SESSION_CAPABILITIES.delete(token);
      sendError(request, response, 403, "That device is not linked to this account.");
      return null;
    }
    if (device.revokedAt) {
      SESSION_CAPABILITIES.delete(token);
      sendError(request, response, 403, "That linked device has been revoked.");
      return null;
    }
  }

  return session;
}

function ensureLegacyRouteEnabled(request, response, routeName) {
  if (ENABLE_LEGACY_API_ROUTES) {
    return true;
  }

  sendError(
    request,
    response,
    410,
    `${routeName} is disabled on production relays. Use the opaque-routing API surface instead.`
  );
  return false;
}

function issueContactHandle({ viewerUserId, targetUserId }) {
  pruneEphemeralPrivacyState();
  const cacheKey = `${viewerUserId}:${targetUserId}`;
  const existingHandle = CONTACT_HANDLE_INDEX.get(cacheKey);
  const existingRecord = existingHandle ? CONTACT_HANDLES.get(existingHandle) : null;
  const now = Date.now();
  if (existingRecord && now + 30_000 < existingRecord.expiresAtMs) {
    return {
      expiresAt: new Date(existingRecord.expiresAtMs).toISOString(),
      handle: existingHandle,
    };
  }

  if (existingHandle) {
    CONTACT_HANDLES.delete(existingHandle);
  }

  const handle = opaqueToken(18);
  const expiresAtMs = now + CONTACT_HANDLE_TTL_MS;
  CONTACT_HANDLES.set(handle, { expiresAtMs, targetUserId, viewerUserId });
  CONTACT_HANDLE_INDEX.set(cacheKey, handle);
  return {
    expiresAt: new Date(expiresAtMs).toISOString(),
    handle,
  };
}

function resolveContactHandle(handle, viewerUserId) {
  pruneEphemeralPrivacyState();
  if (!isNonEmptyString(handle, 256)) {
    return null;
  }

  const record = CONTACT_HANDLES.get(handle.trim());
  if (!record || viewerUserId !== record.viewerUserId || Date.now() >= record.expiresAtMs) {
    CONTACT_HANDLES.delete(handle.trim());
    CONTACT_HANDLE_INDEX.delete(`${record?.viewerUserId ?? ""}:${record?.targetUserId ?? ""}`);
    return null;
  }

  return record.targetUserId;
}

function issueMailboxHandle(threadId) {
  pruneEphemeralPrivacyState();
  const now = Date.now();
  const existing = MAILBOX_ROUTING.get(threadId);
  if (existing && now + 30_000 < existing.expiresAtMs) {
    return {
      expiresAt: new Date(existing.expiresAtMs).toISOString(),
      handle: existing.handle,
    };
  }

  const next = {
    expiresAtMs: now + MAILBOX_HANDLE_TTL_MS,
    handle: opaqueToken(18),
    threadId,
  };
  MAILBOX_ROUTING.set(threadId, next);
  return {
    expiresAt: new Date(next.expiresAtMs).toISOString(),
    handle: next.handle,
  };
}

function resolveMailboxHandle(handle) {
  pruneEphemeralPrivacyState();
  if (!isNonEmptyString(handle, 256)) {
    return null;
  }

  for (const routing of MAILBOX_ROUTING.values()) {
    if (routing.handle === handle.trim() && Date.now() < routing.expiresAtMs) {
      return routing.threadId;
    }
  }

  return null;
}

function issueMailboxCapability({ threadId, userId }) {
  pruneEphemeralPrivacyState();
  const cacheKey = `${threadId}:${userId}`;
  const existingToken = MAILBOX_CAPABILITY_INDEX.get(cacheKey);
  const existingRecord = existingToken ? MAILBOX_CAPABILITIES.get(existingToken) : null;
  const now = Date.now();
  if (existingRecord && now + 30_000 < existingRecord.expiresAtMs) {
    return {
      expiresAt: new Date(existingRecord.expiresAtMs).toISOString(),
      token: existingToken,
    };
  }

  if (existingToken) {
    MAILBOX_CAPABILITIES.delete(existingToken);
  }

  const token = opaqueToken(24);
  const expiresAtMs = now + MAILBOX_CAPABILITY_TTL_MS;
  MAILBOX_CAPABILITIES.set(token, { expiresAtMs, kind: "mailbox", threadId, userId });
  MAILBOX_CAPABILITY_INDEX.set(cacheKey, token);
  return {
    expiresAt: new Date(expiresAtMs).toISOString(),
    token,
  };
}

function requireMailboxCapability(request, response, mailboxHandle) {
  pruneEphemeralPrivacyState();
  const token = readAuthorizationToken(request);
  if (!token) {
    sendError(request, response, 401, "A mailbox capability token is required.");
    return null;
  }

  const record = MAILBOX_CAPABILITIES.get(token);
  if (!record || record.kind !== "mailbox" || Date.now() >= record.expiresAtMs) {
    MAILBOX_CAPABILITIES.delete(token);
    sendError(request, response, 401, "The mailbox capability token has expired. Sync this conversation again.");
    return null;
  }

  const threadId = resolveMailboxHandle(mailboxHandle);
  if (!threadId || threadId !== record.threadId) {
    sendError(request, response, 403, "That mailbox handle is no longer valid for this delivery capability.");
    return null;
  }

  return record;
}

function isTrustedLocalAddress(ipAddress) {
  const value = String(ipAddress ?? "").trim().toLowerCase();
  return (
    value === "127.0.0.1" ||
    value === "::1" ||
    value === "::ffff:127.0.0.1" ||
    value.startsWith("10.") ||
    value.startsWith("192.168.") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(value)
  );
}

function base64urlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64urlDecode(value) {
  const normalized = `${value}`.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = normalized.length % 4;
  const padded = remainder === 0 ? normalized : `${normalized}${"=".repeat(4 - remainder)}`;
  return Buffer.from(padded, "base64");
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

function proofOfWorkSubject(request) {
  return getRequestInstanceKey(request) ?? privacyPreservingRateLimitKey(getRequestIp(request));
}

function createPowChallengeToken({ scope, subject }) {
  const payload = {
    difficultyBits: POW_DIFFICULTY_BITS,
    expiresAt: Date.now() + POW_EXPIRY_MS,
    issuedAt: Date.now(),
    salt: randomBytes(12).toString("hex"),
    scope,
    subject,
  };
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const signature = base64urlEncode(createHmac("sha256", POW_HMAC_KEY).update(encodedPayload).digest());
  return {
    difficultyBits: payload.difficultyBits,
    expiresAt: new Date(payload.expiresAt).toISOString(),
    scope,
    token: `${encodedPayload}.${signature}`,
  };
}

function verifyPowToken(token, { scope, subject }) {
  if (!isNonEmptyString(token, 2_000) || !token.includes(".")) {
    return null;
  }

  const [encodedPayload, encodedSignature] = token.split(".", 2);
  const expectedSignature = base64urlEncode(createHmac("sha256", POW_HMAC_KEY).update(encodedPayload).digest());
  if (expectedSignature !== encodedSignature) {
    return null;
  }

  try {
    const payload = JSON.parse(base64urlDecode(encodedPayload).toString("utf8"));
    if (
      payload.scope !== scope ||
      payload.subject !== subject ||
      typeof payload.expiresAt !== "number" ||
      typeof payload.difficultyBits !== "number" ||
      Date.now() > payload.expiresAt
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function proofOfWorkSatisfied(token, nonce, difficultyBits) {
  if (!isNonEmptyString(nonce, 200)) {
    return false;
  }

  const digest = createHash("sha256").update(`${token}:${nonce.trim()}`).digest();
  return leadingZeroBits(digest) >= difficultyBits;
}

function sendPowChallenge(request, response, scope) {
  const challenge = createPowChallengeToken({
    scope,
    subject: proofOfWorkSubject(request),
  });

  sendJson(request, response, 428, {
    error: `Proof-of-work is required for ${scope} from this client risk tier.`,
    powChallenge: {
      ...challenge,
      nonceField: "X-Notrus-Pow-Nonce",
      tokenField: "X-Notrus-Pow-Token",
    },
  });
}

function shouldRequirePow(request, integrityObservation) {
  if (isTrustedLocalAddress(getRequestIp(request))) {
    return false;
  }

  const riskLevel = integrityObservation?.riskLevel ?? "unknown";
  return riskLevel !== "low";
}

function requireProofOfWork(request, response, scope, integrityObservation) {
  if (!shouldRequirePow(request, integrityObservation)) {
    return true;
  }

  const token = request.headers["x-notrus-pow-token"];
  const nonce = request.headers["x-notrus-pow-nonce"];
  if (typeof token !== "string" || typeof nonce !== "string") {
    sendPowChallenge(request, response, scope);
    return false;
  }

  const payload = verifyPowToken(token.trim(), {
    scope,
    subject: proofOfWorkSubject(request),
  });
  if (!payload || !proofOfWorkSatisfied(token.trim(), nonce.trim(), payload.difficultyBits)) {
    sendPowChallenge(request, response, scope);
    return false;
  }

  return true;
}

function pruneRateLimitBucket(timestamps, windowMs, now) {
  return timestamps.filter((timestamp) => now - timestamp < windowMs);
}

function takeRateLimit(scope, key, { limit, windowMs }) {
  const now = Date.now();
  const bucketId = `${scope}:${key}`;
  const timestamps = pruneRateLimitBucket(RATE_LIMIT_BUCKETS.get(bucketId) ?? [], windowMs, now);

  if (timestamps.length >= limit) {
    RATE_LIMIT_BUCKETS.set(bucketId, timestamps);
    return {
      allowed: false,
      retryAfterMs: Math.max(250, windowMs - (now - timestamps[0])),
    };
  }

  timestamps.push(now);
  RATE_LIMIT_BUCKETS.set(bucketId, timestamps);
  return {
    allowed: true,
    retryAfterMs: 0,
  };
}

function sendJson(request, response, statusCode, payload) {
  setApiHeaders(request, response);
  response.writeHead(statusCode, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(payload));
}

function sendError(request, response, statusCode, message) {
  sendJson(request, response, statusCode, { error: message });
}

function sendRateLimitError(request, response, retryAfterMs, scopeLabel) {
  setApiHeaders(request, response);
  response.setHeader("Retry-After", String(Math.ceil(retryAfterMs / 1000)));
  response.writeHead(429, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(
    JSON.stringify({
      error: `${scopeLabel} rate limit exceeded. Try again in about ${Math.ceil(retryAfterMs / 1000)} seconds.`,
    })
  );
}

function enforceRateLimits(request, response, rules, scopeLabel) {
  for (const rule of rules) {
    const result = takeRateLimit(rule.scope, rule.key, rule.config);
    if (!result.allowed) {
      sendRateLimitError(request, response, result.retryAfterMs, scopeLabel);
      return false;
    }
  }

  return true;
}

function sendText(response, statusCode, message) {
  setSharedHeaders(response);
  response.writeHead(statusCode, {
    "Cache-Control": "no-store",
    "Content-Type": "text/plain; charset=utf-8",
  });
  response.end(message);
}

async function sendStaticAsset(request, response, pathname) {
  const asset = SNAKE_ASSETS.get(pathname);
  if (!asset) {
    return false;
  }

  try {
    const contents = await fs.readFile(asset.filePath);
    setSharedHeaders(response);
    if (asset.contentSecurityPolicy) {
      response.setHeader("Content-Security-Policy", asset.contentSecurityPolicy);
    }
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Length": Buffer.byteLength(contents),
      "Content-Type": asset.contentType,
    });
    if (request.method === "HEAD") {
      response.end();
      return true;
    }
    response.end(contents);
    return true;
  } catch (error) {
    console.error("Failed to serve static asset:", asset.filePath, error);
    sendText(response, 500, "Unable to load the requested asset.");
    return true;
  }
}

function isNonEmptyString(value, maxLength = 500) {
  return typeof value === "string" && value.trim().length > 0 && value.trim().length <= maxLength;
}

function normalizeUsername(value) {
  return value.trim().toLowerCase();
}

function normalizeSearchText(value) {
  return typeof value === "string" ? value.trim().toLowerCase().replace(/[^a-z0-9]/g, "") : "";
}

function normalizeDirectoryCode(value) {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.replace(/[^a-z0-9]/gi, "").toUpperCase();
  return /^[A-F0-9]{12}$/.test(normalized) ? normalized : null;
}

function generateDirectoryCode() {
  return randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase();
}

function ensurePublicJwk(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      typeof value.kty === "string" &&
      typeof value.crv === "string" &&
      typeof value.x === "string" &&
      typeof value.y === "string"
  );
}

function normalizePublicJwk(value) {
  if (!ensurePublicJwk(value)) {
    return null;
  }

  return {
    crv: value.crv.trim(),
    kty: value.kty.trim(),
    x: value.x.trim(),
    y: value.y.trim(),
  };
}

function canonicalEcFingerprintSource(value) {
  const jwk = normalizePublicJwk(value);
  if (!jwk) {
    return null;
  }

  return JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
}

function publicJwksEqual(left, right) {
  const normalizedLeft = normalizePublicJwk(left);
  const normalizedRight = normalizePublicJwk(right);

  return Boolean(
    normalizedLeft &&
      normalizedRight &&
      normalizedLeft.crv === normalizedRight.crv &&
      normalizedLeft.kty === normalizedRight.kty &&
      normalizedLeft.x === normalizedRight.x &&
      normalizedLeft.y === normalizedRight.y
  );
}

function sanitizeSignalBundle(bundle) {
  if (!bundle || typeof bundle !== "object") {
    return null;
  }

  const numericFields = [
    "deviceId",
    "kyberPreKeyId",
    "preKeyId",
    "registrationId",
    "signedPreKeyId",
  ];
  for (const field of numericFields) {
    if (!(typeof bundle[field] === "number" && Number.isInteger(bundle[field]) && bundle[field] > 0)) {
      return null;
    }
  }

  const stringFields = [
    "identityKey",
    "kyberPreKeyPublic",
    "kyberPreKeySignature",
    "preKeyPublic",
    "signedPreKeyPublic",
    "signedPreKeySignature",
  ];
  for (const field of stringFields) {
    if (!isNonEmptyString(bundle[field], 50_000)) {
      return null;
    }
  }

  return {
    deviceId: bundle.deviceId,
    identityKey: bundle.identityKey.trim(),
    kyberPreKeyId: bundle.kyberPreKeyId,
    kyberPreKeyPublic: bundle.kyberPreKeyPublic.trim(),
    kyberPreKeySignature: bundle.kyberPreKeySignature.trim(),
    preKeyId: bundle.preKeyId,
    preKeyPublic: bundle.preKeyPublic.trim(),
    registrationId: bundle.registrationId,
    signedPreKeyId: bundle.signedPreKeyId,
    signedPreKeyPublic: bundle.signedPreKeyPublic.trim(),
    signedPreKeySignature: bundle.signedPreKeySignature.trim(),
  };
}

function signalBundleDigest(bundle) {
  const sanitized = sanitizeSignalBundle(bundle);
  if (!sanitized) {
    return null;
  }

  return createHash("sha256")
    .update(
      JSON.stringify({
        deviceId: sanitized.deviceId,
        identityKey: sanitized.identityKey,
        kyberPreKeyId: sanitized.kyberPreKeyId,
        kyberPreKeyPublic: sanitized.kyberPreKeyPublic,
        kyberPreKeySignature: sanitized.kyberPreKeySignature,
        preKeyId: sanitized.preKeyId,
        preKeyPublic: sanitized.preKeyPublic,
        registrationId: sanitized.registrationId,
        signedPreKeyId: sanitized.signedPreKeyId,
        signedPreKeyPublic: sanitized.signedPreKeyPublic,
        signedPreKeySignature: sanitized.signedPreKeySignature,
      })
    )
    .digest("hex");
}

function signalBundleCanonicalSource(bundle) {
  const sanitized = sanitizeSignalBundle(bundle);
  if (!sanitized) {
    return null;
  }

  return JSON.stringify({
    deviceId: sanitized.deviceId,
    identityKey: sanitized.identityKey,
    kyberPreKeyId: sanitized.kyberPreKeyId,
    kyberPreKeyPublic: sanitized.kyberPreKeyPublic,
    kyberPreKeySignature: sanitized.kyberPreKeySignature,
    preKeyId: sanitized.preKeyId,
    preKeyPublic: sanitized.preKeyPublic,
    registrationId: sanitized.registrationId,
    signedPreKeyId: sanitized.signedPreKeyId,
    signedPreKeyPublic: sanitized.signedPreKeyPublic,
    signedPreKeySignature: sanitized.signedPreKeySignature,
  });
}

function accountResetSignaturePayload(body) {
  return `{"createdAt":${JSON.stringify(body.createdAt)},"displayName":${JSON.stringify(body.displayName)},"encryption":${canonicalEcFingerprintSource(body.encryptionPublicJwk)},"fingerprint":${JSON.stringify(body.fingerprint)},"mlsKeyPackage":${body.mlsKeyPackage ? JSON.stringify(body.mlsKeyPackage.keyPackage) : "null"},"prekeyCreatedAt":${JSON.stringify(body.prekeyCreatedAt)},"prekeyFingerprint":${JSON.stringify(body.prekeyFingerprint)},"prekeyPublicJwk":${canonicalEcFingerprintSource(body.prekeyPublicJwk)},"prekeySignature":${JSON.stringify(body.prekeySignature)},"recoveryFingerprint":${JSON.stringify(body.recoveryFingerprint)},"recoveryPublicJwk":${canonicalEcFingerprintSource(body.recoveryPublicJwk)},"signalBundle":${body.signalBundle ? signalBundleCanonicalSource(body.signalBundle) : "null"},"signing":${canonicalEcFingerprintSource(body.signingPublicJwk)},"userId":${JSON.stringify(body.userId)},"username":${JSON.stringify(body.username)}}`;
}

function verifyRecoverySignature({ recoveryPublicJwk, signature, payload }) {
  if (!normalizePublicJwk(recoveryPublicJwk) || !isNonEmptyString(signature, 20_000)) {
    return false;
  }

  try {
    const keyObject = createPublicKey({ key: recoveryPublicJwk, format: "jwk" });
    return verifySignature("sha256", Buffer.from(payload, "utf8"), keyObject, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

function sanitizeMlsKeyPackage(bundle) {
  if (
    !bundle ||
    typeof bundle !== "object" ||
    !isNonEmptyString(bundle.ciphersuite, 120) ||
    !isNonEmptyString(bundle.keyPackage, 200_000)
  ) {
    return null;
  }

  return {
    ciphersuite: bundle.ciphersuite.trim(),
    keyPackage: bundle.keyPackage.trim(),
  };
}

function sanitizeMlsBootstrap(bootstrap, { creatorId, participantIds }) {
  if (
    !bootstrap ||
    typeof bootstrap !== "object" ||
    !isNonEmptyString(bootstrap.ciphersuite, 120) ||
    !isNonEmptyString(bootstrap.groupId, 50_000)
  ) {
    return null;
  }

  const expectedRecipients = participantIds.filter((participantId) => participantId !== creatorId);
  const welcomes = Array.isArray(bootstrap.welcomes) ? bootstrap.welcomes : [];
  if (welcomes.length !== expectedRecipients.length) {
    return null;
  }

  const sanitizedWelcomes = [];
  for (const welcome of welcomes) {
    if (
      !welcome ||
      !isNonEmptyString(welcome.toUserId, 120) ||
      !expectedRecipients.includes(welcome.toUserId.trim()) ||
      !isNonEmptyString(welcome.welcome, 400_000)
    ) {
      return null;
    }

    sanitizedWelcomes.push({
      toUserId: welcome.toUserId.trim(),
      welcome: welcome.welcome.trim(),
    });
  }

  if (new Set(sanitizedWelcomes.map((welcome) => welcome.toUserId)).size !== expectedRecipients.length) {
    return null;
  }

  return {
    ciphersuite: bootstrap.ciphersuite.trim(),
    groupId: bootstrap.groupId.trim(),
    welcomes: sanitizedWelcomes.sort((left, right) => left.toUserId.localeCompare(right.toUserId)),
  };
}

function normalizeUserRecord(user) {
  if (!user || typeof user !== "object") {
    return user;
  }

  return {
    ...user,
    deviceEvents: Array.isArray(user.deviceEvents)
      ? user.deviceEvents.map((event) => sanitizeDeviceEventRecord(event)).filter(Boolean)
      : [],
    devices: Array.isArray(user.devices)
      ? user.devices.map((device) => sanitizeDeviceRecord(device)).filter(Boolean)
      : [],
    directoryCode: normalizeDirectoryCode(user.directoryCode) ?? generateDirectoryCode(),
    encryptionPublicJwk: normalizePublicJwk(user.encryptionPublicJwk),
    integrityObservation: sanitizeIntegrityObservation(user.integrityObservation),
    mlsKeyPackage: sanitizeMlsKeyPackage(user.mlsKeyPackage),
    prekeyPublicJwk: normalizePublicJwk(user.prekeyPublicJwk),
    recoveryPublicJwk: normalizePublicJwk(user.recoveryPublicJwk),
    signalBundle: sanitizeSignalBundle(user.signalBundle),
    signalBundleDigest: signalBundleDigest(user.signalBundle),
    signingPublicJwk: normalizePublicJwk(user.signingPublicJwk),
  };
}

function normalizeThreadRecord(thread) {
  if (!thread || typeof thread !== "object") {
    return thread;
  }

  return {
    ...thread,
    initialRatchetPublicJwk: normalizePublicJwk(thread.initialRatchetPublicJwk),
    mlsBootstrap: thread.mlsBootstrap
      ? sanitizeMlsBootstrap(thread.mlsBootstrap, {
          creatorId: thread.createdBy,
          participantIds: Array.isArray(thread.participantIds) ? thread.participantIds : [],
        })
      : null,
    messages: Array.isArray(thread.messages)
      ? thread.messages.map((message) => ({
          ...message,
          messageKind: isNonEmptyString(message.messageKind, 80) ? message.messageKind.trim() : null,
          wireMessage: isNonEmptyString(message.wireMessage, 400_000) ? message.wireMessage.trim() : null,
          ratchetPublicJwk: normalizePublicJwk(message.ratchetPublicJwk),
        }))
      : [],
    attachments: Array.isArray(thread.attachments)
      ? thread.attachments.map((attachment) => ({
          ...attachment,
          ciphertext: isNonEmptyString(attachment.ciphertext, 8_000_000) ? attachment.ciphertext.trim() : null,
          iv: isNonEmptyString(attachment.iv, 400) ? attachment.iv.trim() : null,
          sha256: isNonEmptyString(attachment.sha256, 200) ? attachment.sha256.trim() : null,
        }))
      : [],
  };
}

function normalizeAbuseReportRecord(report) {
  if (
    !report ||
    typeof report !== "object" ||
    !isNonEmptyString(report.id, 120) ||
    !isNonEmptyString(report.createdAt, 60) ||
    !isNonEmptyString(report.reason, 80) ||
    !isNonEmptyString(report.reporterId, 120) ||
    !isNonEmptyString(report.targetUserId, 120)
  ) {
    return null;
  }

  return {
    id: report.id.trim(),
    createdAt: report.createdAt.trim(),
    messageIds: dedupeStringArray(report.messageIds, 120).slice(0, 20),
    reason: report.reason.trim(),
    reporterId: report.reporterId.trim(),
    targetUserId: report.targetUserId.trim(),
    threadId: isNonEmptyString(report.threadId, 160) ? report.threadId.trim() : null,
  };
}

function parseIntegrityReportHeader(request) {
  const encoded = request.headers["x-notrus-integrity"];
  if (typeof encoded !== "string" || !encoded.trim()) {
    return null;
  }

  try {
    return JSON.parse(Buffer.from(encoded.trim(), "base64").toString("utf8"));
  } catch {
    return null;
  }
}

function sanitizeIntegrityObservation(observation) {
  if (!observation || typeof observation !== "object") {
    return null;
  }

  const bundleIdentifier = isNonEmptyString(observation.bundleIdentifier, 200)
    ? observation.bundleIdentifier.trim()
    : null;
  const codeSignatureStatus = isNonEmptyString(observation.codeSignatureStatus, 40)
    ? observation.codeSignatureStatus.trim()
    : null;
  const deviceCheckStatus = isNonEmptyString(observation.deviceCheckStatus, 40)
    ? observation.deviceCheckStatus.trim()
    : null;
  const riskLevel = isNonEmptyString(observation.riskLevel, 40) ? observation.riskLevel.trim() : null;
  const generatedAt = isNonEmptyString(observation.generatedAt, 60) ? observation.generatedAt.trim() : null;
  const note = isNonEmptyString(observation.note, 300) ? observation.note.trim() : null;
  const deviceCheckTokenPresented =
    observation.deviceCheckTokenPresented === true || isNonEmptyString(observation.deviceCheckToken, 16_000);
  const playIntegrityTokenPresented =
    observation.playIntegrityTokenPresented === true || isNonEmptyString(observation.playIntegrityToken, 16_000);

  if (!bundleIdentifier || !codeSignatureStatus || !deviceCheckStatus || !riskLevel || !generatedAt) {
    return null;
  }

  return {
    bundleIdentifier,
    codeSignatureStatus,
    deviceCheckStatus,
    deviceCheckTokenPresented,
    generatedAt,
    note,
    playIntegrityTokenPresented,
    riskLevel,
  };
}

function sanitizeIntegrityProofTokens(observation) {
  if (!observation || typeof observation !== "object") {
    return null;
  }

  const deviceCheckToken = isNonEmptyString(observation.deviceCheckToken, 16_000)
    ? observation.deviceCheckToken.trim()
    : null;
  const playIntegrityToken = isNonEmptyString(observation.playIntegrityToken, 16_000)
    ? observation.playIntegrityToken.trim()
    : null;

  if (!deviceCheckToken && !playIntegrityToken) {
    return null;
  }

  return {
    deviceCheckToken,
    playIntegrityToken,
  };
}

function sanitizeDeviceRecord(device) {
  if (
    !device ||
    typeof device !== "object" ||
    !isNonEmptyString(device.id, 120) ||
    !isNonEmptyString(device.label, 80) ||
    !isNonEmptyString(device.platform, 40) ||
    !ensurePublicJwk(device.publicJwk) ||
    !isNonEmptyString(device.createdAt, 60)
  ) {
    return null;
  }

  const revokedAt = isNonEmptyString(device.revokedAt, 60) ? device.revokedAt.trim() : null;
  const updatedAt = isNonEmptyString(device.updatedAt, 60) ? device.updatedAt.trim() : device.createdAt.trim();
  const storageMode = isNonEmptyString(device.storageMode, 60) ? device.storageMode.trim() : null;
  const riskLevel = isNonEmptyString(device.riskLevel, 40) ? device.riskLevel.trim() : "unknown";
  const attestationNote = isNonEmptyString(device.attestationNote, 300) ? device.attestationNote.trim() : null;
  const attestationStatus = isNonEmptyString(device.attestationStatus, 60) ? device.attestationStatus.trim() : null;
  const attestedAt = isNonEmptyString(device.attestedAt, 60) ? device.attestedAt.trim() : null;

  return {
    attestationNote,
    attestationStatus,
    attestedAt,
    createdAt: device.createdAt.trim(),
    id: device.id.trim(),
    label: device.label.trim(),
    platform: device.platform.trim(),
    publicJwk: normalizePublicJwk(device.publicJwk),
    revokedAt,
    riskLevel,
    storageMode,
    updatedAt,
  };
}

function sanitizeDeviceAttestationPayload(attestation) {
  if (!attestation || typeof attestation !== "object") {
    return null;
  }

  const publicJwk = normalizePublicJwk(attestation.publicJwk);
  const proofPayload = isNonEmptyString(attestation.proofPayload, 8_000) ? attestation.proofPayload.trim() : null;
  const proofSignature = isNonEmptyString(attestation.proofSignature, 8_000) ? attestation.proofSignature.trim() : null;
  const generatedAt = isNonEmptyString(attestation.generatedAt, 60) ? attestation.generatedAt.trim() : null;
  const keyFingerprint = isNonEmptyString(attestation.keyFingerprint, 200) ? attestation.keyFingerprint.trim() : null;
  const keyRole = isNonEmptyString(attestation.keyRole, 80) ? attestation.keyRole.trim() : null;
  const certificateChain = Array.isArray(attestation.certificateChain)
    ? attestation.certificateChain
        .filter((value) => isNonEmptyString(value, 16_000))
        .map((value) => value.trim())
        .slice(0, 8)
    : [];

  if (!publicJwk || !proofPayload || !proofSignature || !generatedAt || !keyFingerprint || !keyRole) {
    return null;
  }

  return {
    certificateChain,
    generatedAt,
    keyFingerprint,
    keyRole,
    proofPayload,
    proofSignature,
    publicJwk,
  };
}

async function verifyAndroidAttestationWithService(attestation) {
  if (!attestation) {
    return null;
  }

  return verifyAttestationWithService("/api/attestation/android/verify", attestation);
}

async function verifyAppleDeviceCheckWithService({
  bundleIdentifier,
  deviceCheckToken,
  deviceId = null,
  generatedAt = null,
}) {
  if (!deviceCheckToken) {
    return null;
  }

  return verifyAttestationWithService("/api/attestation/apple/devicecheck/verify", {
    bundleIdentifier,
    deviceCheckToken,
    deviceId,
    generatedAt,
  });
}

async function verifyAndroidPlayIntegrityWithService({
  bundleIdentifier,
  deviceId = null,
  generatedAt = null,
  playIntegrityToken,
}) {
  if (!playIntegrityToken) {
    return null;
  }

  return verifyAttestationWithService("/api/attestation/android/play-integrity/verify", {
    bundleIdentifier,
    deviceId,
    generatedAt,
    playIntegrityToken,
  });
}

async function verifyAttestationWithService(pathname, payload) {
  if (!ATTESTATION_ORIGIN) {
    return {
      note: "Attestation verification service was not configured on this relay.",
      status: "unverified",
      verified: false,
      verifiedAt: new Date().toISOString(),
    };
  }

  try {
    const response = await fetch(new URL(pathname, ATTESTATION_ORIGIN), {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      return {
        note: `Attestation service returned ${response.status}.`,
        status: "unverified",
        verified: false,
        verifiedAt: new Date().toISOString(),
      };
    }

    const decodedPayload = await response.json();
    return {
      note: isNonEmptyString(decodedPayload.note, 300) ? decodedPayload.note.trim() : null,
      status: isNonEmptyString(decodedPayload.status, 60) ? decodedPayload.status.trim() : "unverified",
      verified: decodedPayload.verified === true,
      verifiedAt: isNonEmptyString(decodedPayload.verifiedAt, 60)
        ? decodedPayload.verifiedAt.trim()
        : new Date().toISOString(),
    };
  } catch (error) {
    const detail = isNonEmptyString(error?.message, 200) ? error.message.trim() : null;
    return {
      note: detail
        ? `Attestation verification service was unreachable. ${detail}`
        : "Attestation verification service was unreachable.",
      status: "unverified",
      verified: false,
      verifiedAt: new Date().toISOString(),
    };
  }
}

function mergeVerificationSummaries(summaries) {
  const filtered = summaries.filter(Boolean);
  if (filtered.length === 0) {
    return null;
  }

  const verified = filtered.every((summary) => summary.verified === true);
  const status = filtered
    .map((summary) => (isNonEmptyString(summary.status, 60) ? summary.status.trim() : null))
    .filter(Boolean)
    .join("+")
    .slice(0, 60) || "unverified";
  const note = filtered
    .map((summary) => (isNonEmptyString(summary.note, 300) ? summary.note.trim() : null))
    .filter(Boolean)
    .join(" | ")
    .slice(0, 300) || null;
  const verifiedAt = filtered
    .map((summary) => (isNonEmptyString(summary.verifiedAt, 60) ? summary.verifiedAt.trim() : null))
    .find(Boolean) ?? new Date().toISOString();

  return {
    note,
    status,
    verified,
    verifiedAt,
  };
}

function sanitizeDeviceEventRecord(event) {
  if (
    !event ||
    typeof event !== "object" ||
    !isNonEmptyString(event.id, 120) ||
    !isNonEmptyString(event.kind, 40) ||
    !isNonEmptyString(event.createdAt, 60) ||
    !isNonEmptyString(event.deviceId, 120)
  ) {
    return null;
  }

  return {
    actorDeviceId: isNonEmptyString(event.actorDeviceId, 120) ? event.actorDeviceId.trim() : null,
    createdAt: event.createdAt.trim(),
    deviceId: event.deviceId.trim(),
    id: event.id.trim(),
    kind: event.kind.trim(),
    label: isNonEmptyString(event.label, 80) ? event.label.trim() : null,
    platform: isNonEmptyString(event.platform, 40) ? event.platform.trim() : null,
    revokedAt: isNonEmptyString(event.revokedAt, 60) ? event.revokedAt.trim() : null,
  };
}

function sanitizeDeviceEnrollment(device) {
  if (
    !device ||
    typeof device !== "object" ||
    !isNonEmptyString(device.id, 120) ||
    !isNonEmptyString(device.label, 80) ||
    !isNonEmptyString(device.platform, 40) ||
    !ensurePublicJwk(device.publicJwk)
  ) {
    return null;
  }

  return {
    createdAt: isNonEmptyString(device.createdAt, 60) ? device.createdAt.trim() : new Date().toISOString(),
    id: device.id.trim(),
    label: device.label.trim(),
    platform: device.platform.trim(),
    publicJwk: normalizePublicJwk(device.publicJwk),
    riskLevel: isNonEmptyString(device.riskLevel, 40) ? device.riskLevel.trim() : "unknown",
    storageMode: isNonEmptyString(device.storageMode, 60) ? device.storageMode.trim() : null,
  };
}

function publicDeviceRecord(device, { currentDeviceId = null } = {}) {
  return {
    attestationNote: device.attestationNote ?? null,
    attestationStatus: device.attestationStatus ?? null,
    attestedAt: device.attestedAt ?? null,
    createdAt: device.createdAt,
    current: currentDeviceId === device.id,
    id: device.id,
    label: device.label,
    platform: device.platform,
    revokedAt: device.revokedAt ?? null,
    riskLevel: device.riskLevel ?? "unknown",
    storageMode: device.storageMode ?? null,
    updatedAt: device.updatedAt ?? device.createdAt,
  };
}

function deviceActionSignaturePayload({ action, createdAt, signerDeviceId, targetDeviceId, userId }) {
  return JSON.stringify({
    action,
    createdAt,
    signerDeviceId,
    targetDeviceId,
    userId,
  });
}

function publicDeviceEventRecord(event) {
  return {
    actorDeviceId: event.actorDeviceId ?? null,
    createdAt: event.createdAt,
    deviceId: event.deviceId,
    id: event.id,
    kind: event.kind,
    label: event.label ?? null,
    platform: event.platform ?? null,
    revokedAt: event.revokedAt ?? null,
  };
}

function findUserDevice(user, deviceId) {
  return Array.isArray(user?.devices) ? user.devices.find((device) => device.id === deviceId) ?? null : null;
}

function getRequestDeviceId(request) {
  const deviceId = request.headers["x-notrus-device-id"];
  return isNonEmptyString(deviceId, 120) ? deviceId.trim() : null;
}

function recordDeviceEvent(user, event) {
  user.deviceEvents = Array.isArray(user.deviceEvents) ? user.deviceEvents : [];
  user.deviceEvents.push({
    actorDeviceId: event.actorDeviceId ?? null,
    createdAt: event.createdAt,
    deviceId: event.deviceId,
    id: randomUUID(),
    kind: event.kind,
    label: event.label ?? null,
    platform: event.platform ?? null,
    revokedAt: event.revokedAt ?? null,
  });
  user.deviceEvents = user.deviceEvents
    .sort((left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime())
    .slice(0, 100);
}

function upsertUserDevice(user, enrollment, { actorDeviceId = null, attestationSummary = null, integrityObservation = null, now }) {
  if (!enrollment) {
    return null;
  }

  user.devices = Array.isArray(user.devices) ? user.devices : [];
  const existing = user.devices.find((device) => device.id === enrollment.id) ?? null;
  if (existing?.revokedAt) {
    return { error: "That linked device has been revoked and cannot silently re-enroll." };
  }

  const riskLevel = integrityObservation?.riskLevel ?? enrollment.riskLevel ?? "unknown";
  if (existing) {
    existing.attestationNote = attestationSummary?.note ?? existing.attestationNote ?? null;
    existing.attestationStatus = attestationSummary?.status ?? existing.attestationStatus ?? null;
    existing.attestedAt = attestationSummary?.verifiedAt ?? existing.attestedAt ?? null;
    existing.label = enrollment.label;
    existing.platform = enrollment.platform;
    existing.publicJwk = enrollment.publicJwk;
    existing.riskLevel = riskLevel;
    existing.storageMode = enrollment.storageMode ?? existing.storageMode ?? null;
    existing.updatedAt = now;
    return { added: false, device: existing };
  }

  const deviceRecord = {
    attestationNote: attestationSummary?.note ?? null,
    attestationStatus: attestationSummary?.status ?? null,
    attestedAt: attestationSummary?.verifiedAt ?? null,
    createdAt: enrollment.createdAt,
    id: enrollment.id,
    label: enrollment.label,
    platform: enrollment.platform,
    publicJwk: enrollment.publicJwk,
    revokedAt: null,
    riskLevel,
    storageMode: enrollment.storageMode ?? null,
    updatedAt: now,
  };
  user.devices.push(deviceRecord);
  recordDeviceEvent(user, {
    actorDeviceId,
    createdAt: now,
    deviceId: deviceRecord.id,
    kind: "device-added",
    label: deviceRecord.label,
    platform: deviceRecord.platform,
  });
  return { added: true, device: deviceRecord };
}

function verifyDeviceActionSignature({ device, signature, payload }) {
  if (!device || !isNonEmptyString(signature, 20_000)) {
    return false;
  }

  try {
    const publicKey = createPublicKey({
      format: "jwk",
      key: device.publicJwk,
    });
    return verifySignature(
      "sha256",
      Buffer.from(payload, "utf8"),
      publicKey,
      Buffer.from(signature.trim(), "base64")
    );
  } catch {
    return false;
  }
}

function integrityRiskSummary() {
  return Object.values(store.users).reduce(
    (summary, user) => {
      const risk = user.integrityObservation?.riskLevel ?? "unknown";
      summary[risk] = (summary[risk] ?? 0) + 1;
      return summary;
    },
    { high: 0, low: 0, medium: 0, unknown: 0 }
  );
}

function dedupeStringArray(values, maxLength = 120) {
  return [...new Set(Array.isArray(values) ? values.filter((value) => isNonEmptyString(value, maxLength)).map((value) => value.trim()) : [])];
}

function ensureKnownProtocol(protocolName) {
  return Boolean(getProtocolSpec(protocolName));
}

function haveSameMembers(left, right) {
  if (left.length !== right.length) {
    return false;
  }

  const sortedLeft = [...left].sort();
  const sortedRight = [...right].sort();
  return sortedLeft.every((value, index) => value === sortedRight[index]);
}

function sanitizeEnvelopeRecord(envelope, { allowedRecipients, expectedFromUserId, expectedThreadId }) {
  if (
    !envelope ||
    !isNonEmptyString(envelope.threadId, 160) ||
    !isNonEmptyString(envelope.fromUserId, 120) ||
    !isNonEmptyString(envelope.toUserId, 120) ||
    !isNonEmptyString(envelope.createdAt, 60) ||
    !isNonEmptyString(envelope.iv, 400) ||
    !isNonEmptyString(envelope.ciphertext, 20_000) ||
    !isNonEmptyString(envelope.signature, 20_000)
  ) {
    return null;
  }

  if (
    envelope.threadId !== expectedThreadId ||
    envelope.fromUserId !== expectedFromUserId ||
    !allowedRecipients.includes(envelope.toUserId)
  ) {
    return null;
  }

  return {
    threadId: envelope.threadId,
    fromUserId: envelope.fromUserId,
    toUserId: envelope.toUserId,
    createdAt: envelope.createdAt,
    iv: envelope.iv,
    ciphertext: envelope.ciphertext,
    signature: envelope.signature,
  };
}

function sanitizeGroupState(groupState, expectedParticipants) {
  if (!groupState || typeof groupState !== "object") {
    return null;
  }

  const epoch =
    typeof groupState.epoch === "number" && Number.isInteger(groupState.epoch) && groupState.epoch >= 1
      ? groupState.epoch
      : null;
  const participantIds = dedupeStringArray(groupState.participantIds);
  const treeHash = isNonEmptyString(groupState.treeHash, 200) ? groupState.treeHash.trim() : null;
  const transcriptHash = isNonEmptyString(groupState.transcriptHash, 200) ? groupState.transcriptHash.trim() : null;

  if (!epoch || !treeHash || !transcriptHash || !haveSameMembers(participantIds, expectedParticipants)) {
    return null;
  }

  return {
    epoch,
    participantIds,
    transcriptHash,
    treeHash,
  };
}

function sanitizeGroupCommit(groupCommit, { createdAt, senderId, threadId }) {
  if (!groupCommit || typeof groupCommit !== "object") {
    return null;
  }

  const epoch =
    typeof groupCommit.epoch === "number" && Number.isInteger(groupCommit.epoch) && groupCommit.epoch >= 2
      ? groupCommit.epoch
      : null;
  const commitType = isNonEmptyString(groupCommit.commitType, 40) ? groupCommit.commitType.trim() : "rotate";
  const parentTranscriptHash = isNonEmptyString(groupCommit.parentTranscriptHash, 200)
    ? groupCommit.parentTranscriptHash.trim()
    : null;
  const participantIds = dedupeStringArray(groupCommit.participantIds);
  const addedIds = dedupeStringArray(groupCommit.addedIds);
  const removedIds = dedupeStringArray(groupCommit.removedIds);
  const treeHash = isNonEmptyString(groupCommit.treeHash, 200) ? groupCommit.treeHash.trim() : null;
  const transcriptHash = isNonEmptyString(groupCommit.transcriptHash, 200) ? groupCommit.transcriptHash.trim() : null;

  if (!epoch || !treeHash || !transcriptHash || !parentTranscriptHash) {
    return null;
  }

  if (!participantIds.includes(senderId) || participantIds.length < 3 || participantIds.length > MAX_THREAD_PARTICIPANTS) {
    return null;
  }

  const envelopeThreadId = `${threadId}:epoch:${epoch}`;
  const envelopes = Array.isArray(groupCommit.envelopes) ? groupCommit.envelopes : [];
  if (envelopes.length !== participantIds.length) {
    return null;
  }

  const sanitizedEnvelopes = [];
  for (const envelope of envelopes) {
    const sanitized = sanitizeEnvelopeRecord(envelope, {
      allowedRecipients: participantIds,
      expectedFromUserId: senderId,
      expectedThreadId: envelopeThreadId,
    });
    if (!sanitized) {
      return null;
    }

    sanitizedEnvelopes.push(sanitized);
  }

  if (new Set(sanitizedEnvelopes.map((envelope) => envelope.toUserId)).size !== participantIds.length) {
    return null;
  }

  return {
    addedIds,
    commitType,
    committedAt: createdAt,
    committedBy: senderId,
    envelopes: sanitizedEnvelopes.sort(sortByDateAscending),
    epoch,
    parentTranscriptHash,
    participantIds,
    removedIds,
    transcriptHash,
    treeHash,
  };
}

function sanitizeAttachmentRecord(attachment, { senderId, threadId }) {
  if (
    !attachment ||
    !isNonEmptyString(attachment.id, 120) ||
    !isNonEmptyString(attachment.createdAt, 60) ||
    !isNonEmptyString(attachment.iv, 400) ||
    !isNonEmptyString(attachment.ciphertext, 8_000_000) ||
    !isNonEmptyString(attachment.sha256, 200)
  ) {
    return null;
  }

  const byteLength =
    typeof attachment.byteLength === "number" && Number.isInteger(attachment.byteLength) && attachment.byteLength > 0
      ? attachment.byteLength
      : null;
  if (!byteLength) {
    return null;
  }

  const attachmentSenderId = isNonEmptyString(attachment.senderId, 120) ? attachment.senderId.trim() : senderId;
  const attachmentThreadId = isNonEmptyString(attachment.threadId, 160) ? attachment.threadId.trim() : threadId;

  if (attachmentSenderId !== senderId || attachmentThreadId !== threadId) {
    return null;
  }

  return {
    byteLength,
    ciphertext: attachment.ciphertext.trim(),
    createdAt: attachment.createdAt.trim(),
    id: attachment.id.trim(),
    iv: attachment.iv.trim(),
    senderId: attachmentSenderId,
    sha256: attachment.sha256.trim(),
    threadId: attachmentThreadId,
  };
}

function publicUserRecord(user, { viewerUserId = null } = {}) {
  const contactHandle =
    viewerUserId && viewerUserId !== user.id && !user.deactivatedAt
      ? issueContactHandle({ targetUserId: user.id, viewerUserId })
      : null;

  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    ...(viewerUserId === user.id ? { directoryCode: user.directoryCode ?? null } : {}),
    ...(contactHandle ? { contactHandle: contactHandle.handle } : {}),
    fingerprint: user.fingerprint,
    mlsKeyPackage: user.mlsKeyPackage ?? null,
    prekeyCreatedAt: user.prekeyCreatedAt ?? null,
    prekeyFingerprint: user.prekeyFingerprint ?? null,
    prekeyPublicJwk: user.prekeyPublicJwk ?? null,
    prekeySignature: user.prekeySignature ?? null,
    signalBundle: user.signalBundle ?? null,
    signingPublicJwk: user.signingPublicJwk,
    encryptionPublicJwk: user.encryptionPublicJwk,
    createdAt: user.createdAt,
  };
}

function publicTransparencyEntry(entry) {
  return {
    createdAt: entry.createdAt,
    entryHash: entry.entryHash,
    fingerprint: entry.fingerprint,
    kind: entry.kind,
    prekeyFingerprint: entry.prekeyFingerprint ?? null,
    previousHash: entry.previousHash,
    sequence: entry.sequence,
    userId: entry.userId,
    username: entry.username,
  };
}

function hashTransparencyEntry(entry) {
  return createHash("sha256")
    .update(
      JSON.stringify({
        createdAt: entry.createdAt,
        fingerprint: entry.fingerprint,
        kind: entry.kind,
        prekeyFingerprint: entry.prekeyFingerprint ?? null,
        previousHash: entry.previousHash ?? null,
        sequence: entry.sequence,
        userId: entry.userId,
        username: entry.username,
      })
    )
    .digest("hex");
}

function normalizeTransparencyLog(rawEntries) {
  const safeEntries = Array.isArray(rawEntries) ? rawEntries : [];
  const entries = [];
  let previousHash = null;
  let wasNormalized = false;

  safeEntries.forEach((entry, index) => {
    if (!entry || typeof entry !== "object") {
      wasNormalized = true;
      return;
    }

    const normalizedEntry = {
      createdAt: isNonEmptyString(entry.createdAt, 200) ? entry.createdAt.trim() : new Date(0).toISOString(),
      fingerprint: isNonEmptyString(entry.fingerprint, 512) ? entry.fingerprint.trim() : "unknown",
      kind: isNonEmptyString(entry.kind, 200) ? entry.kind.trim() : "unknown",
      prekeyFingerprint: isNonEmptyString(entry.prekeyFingerprint, 512) ? entry.prekeyFingerprint.trim() : null,
      previousHash,
      sequence: index + 1,
      userId: isNonEmptyString(entry.userId, 256) ? entry.userId.trim() : `legacy-user-${index + 1}`,
      username: isNonEmptyString(entry.username, 256) ? entry.username.trim() : `legacy-user-${index + 1}`,
    };
    normalizedEntry.entryHash = hashTransparencyEntry(normalizedEntry);

    if (
      entry.previousHash !== normalizedEntry.previousHash ||
      entry.sequence !== normalizedEntry.sequence ||
      entry.entryHash !== normalizedEntry.entryHash
    ) {
      wasNormalized = true;
    }

    entries.push(normalizedEntry);
    previousHash = normalizedEntry.entryHash;
  });

  return {
    entries,
    head: previousHash,
    wasNormalized,
  };
}

function appendTransparencyEntry({ createdAt, fingerprint, kind, prekeyFingerprint, userId, username }) {
  const entry = {
    createdAt,
    fingerprint,
    kind,
    prekeyFingerprint: prekeyFingerprint ?? null,
    previousHash: store.transparencyHead,
    sequence: store.transparencyLog.length + 1,
    userId,
    username,
  };

  entry.entryHash = hashTransparencyEntry(entry);
  store.transparencyLog.push(entry);
  store.transparencyHead = entry.entryHash;
}

function sortByDateAscending(left, right) {
  return new Date(left.createdAt).getTime() - new Date(right.createdAt).getTime();
}

function isExpired(isoString, retentionMs) {
  const timestamp = new Date(isoString).getTime();
  if (Number.isNaN(timestamp)) {
    return false;
  }
  return Date.now() - timestamp > retentionMs;
}

function pruneExpiredArtifacts() {
  let mutated = false;

  for (const thread of Object.values(store.threads)) {
    const keptMessages = thread.messages.filter((message) => !isExpired(message.createdAt, MESSAGE_RETENTION_MS));
    if (keptMessages.length !== thread.messages.length) {
      thread.messages = keptMessages;
      mutated = true;
    }

    const keptAttachments = thread.attachments.filter((attachment) => !isExpired(attachment.createdAt, ATTACHMENT_RETENTION_MS));
    if (keptAttachments.length !== thread.attachments.length) {
      thread.attachments = keptAttachments;
      mutated = true;
    }
  }

  const keptReports = store.reports.filter((report) => !isExpired(report.createdAt, REPORT_RETENTION_MS));
  if (keptReports.length !== store.reports.length) {
    store.reports = keptReports;
    mutated = true;
  }

  for (const user of Object.values(store.users)) {
    const events = Array.isArray(user.deviceEvents) ? user.deviceEvents : [];
    const keptEvents = events.filter((event) => !isExpired(event.createdAt, DEVICE_EVENT_RETENTION_MS));
    if (keptEvents.length !== events.length) {
      user.deviceEvents = keptEvents;
      mutated = true;
    }
  }

  if (mutated) {
    queuePersist();
  }
}

function relatedUserIdsFor(userId) {
  const related = new Set([userId]);
  for (const thread of Object.values(store.threads)) {
    if (thread.participantIds.includes(userId)) {
      for (const participantId of thread.participantIds) {
        related.add(participantId);
      }
    }
  }
  return [...related];
}

function searchDirectoryRecords(query, requestingUserId, { exactUsernameOrInviteOnly = false } = {}) {
  const normalizedDirectoryCode = normalizeDirectoryCode(query);
  const normalizedCompact = normalizeSearchText(query);
  if (exactUsernameOrInviteOnly) {
    const normalizedUsername = normalizeUsername(query);
    return Object.values(store.users)
      .filter((user) => user.id !== requestingUserId)
      .filter((user) => !user.deactivatedAt)
      .filter((user) => {
        const compactUsername = normalizeSearchText(user.username);
        const compactDisplayName = normalizeSearchText(user.displayName);
        if (normalizedDirectoryCode) {
          return user.directoryCode === normalizedDirectoryCode || user.directoryCode?.startsWith(normalizedDirectoryCode);
        }
        return (
          user.username === normalizedUsername ||
          user.username.startsWith(normalizedUsername) ||
          user.displayName.toLowerCase().includes(normalizedUsername) ||
          (normalizedCompact.length >= 2 &&
            (compactUsername.includes(normalizedCompact) || compactDisplayName.includes(normalizedCompact)))
        );
      })
      .sort((left, right) => {
        const rank = (user) => {
          const compactUsername = normalizeSearchText(user.username);
          const compactDisplayName = normalizeSearchText(user.displayName);
          if (normalizedDirectoryCode && user.directoryCode === normalizedDirectoryCode) {
            return 0;
          }
          if (user.username === normalizedUsername) {
            return 1;
          }
          if (user.username.startsWith(normalizedUsername)) {
            return 2;
          }
          if (normalizedCompact.length >= 2 && compactUsername.startsWith(normalizedCompact)) {
            return 3;
          }
          if (normalizedCompact.length >= 2 && compactUsername.includes(normalizedCompact)) {
            return 4;
          }
          if (normalizedCompact.length >= 2 && compactDisplayName.includes(normalizedCompact)) {
            return 5;
          }
          return 6;
        };
        const leftRank = rank(left);
        const rightRank = rank(right);
        if (leftRank !== rightRank) {
          return leftRank - rightRank;
        }
        return left.username.localeCompare(right.username);
      })
      .slice(0, DIRECTORY_SEARCH_LIMIT)
      .map((user) => publicUserRecord(user, { viewerUserId: requestingUserId }));
  }

  const normalized = normalizeUsername(query);
  return Object.values(store.users)
    .filter((user) => user.id !== requestingUserId)
    .filter((user) => !user.deactivatedAt)
    .filter((user) => {
      const compactUsername = normalizeSearchText(user.username);
      const compactDisplayName = normalizeSearchText(user.displayName);
      return (
        user.username.includes(normalized) ||
        user.displayName.toLowerCase().includes(normalized) ||
        (normalizedCompact.length >= 2 &&
          (compactUsername.includes(normalizedCompact) || compactDisplayName.includes(normalizedCompact)))
      );
    })
    .sort((left, right) => {
      const rank = (user) => {
        const compactUsername = normalizeSearchText(user.username);
        const compactDisplayName = normalizeSearchText(user.displayName);
        if (user.username.startsWith(normalized)) {
          return 0;
        }
        if (normalizedCompact.length >= 2 && compactUsername.startsWith(normalizedCompact)) {
          return 1;
        }
        if (user.displayName.toLowerCase().includes(normalized)) {
          return 2;
        }
        if (normalizedCompact.length >= 2 && compactDisplayName.includes(normalizedCompact)) {
          return 3;
        }
        return 4;
      };
      const leftRank = rank(left);
      const rightRank = rank(right);
      if (leftRank !== rightRank) {
        return leftRank - rightRank;
      }
      return left.username.localeCompare(right.username);
    })
    .slice(0, DIRECTORY_SEARCH_LIMIT)
    .map((user) => publicUserRecord(user, { viewerUserId: requestingUserId }));
}

function storedAccountMatchesRegistration(user, body, { username, fingerprint, recoveryFingerprint }) {
  if (user.deactivatedAt) {
    return false;
  }
  return (
    user.username === username &&
    user.fingerprint === fingerprint &&
    user.recoveryFingerprint === recoveryFingerprint &&
    publicJwksEqual(user.signingPublicJwk, body.signingPublicJwk) &&
    publicJwksEqual(user.encryptionPublicJwk, body.encryptionPublicJwk) &&
    publicJwksEqual(user.recoveryPublicJwk, body.recoveryPublicJwk)
  );
}

function sanitizeThreadForUser(thread, userId) {
  const mailboxHandle = issueMailboxHandle(thread.id);
  const deliveryCapability = issueMailboxCapability({ threadId: thread.id, userId });
  return {
    deliveryCapability: deliveryCapability.token,
    id: thread.id,
    groupState: thread.groupState
      ? {
          epoch: thread.groupState.epoch,
          participantIds: [...thread.groupState.participantIds],
          transcriptHash: thread.groupState.transcriptHash,
          treeHash: thread.groupState.treeHash,
        }
      : null,
    initialRatchetPublicJwk: thread.initialRatchetPublicJwk ?? null,
    mlsBootstrap: thread.mlsBootstrap
      ? {
          ciphersuite: thread.mlsBootstrap.ciphersuite,
          groupId: thread.mlsBootstrap.groupId,
          welcomes: thread.mlsBootstrap.welcomes.filter((welcome) => welcome.toUserId === userId),
        }
      : null,
    mailboxHandle: mailboxHandle.handle,
    title: thread.title,
    protocol: thread.protocol ?? "static-room-v1",
    createdAt: thread.createdAt,
    createdBy: thread.createdBy,
    participantIds: [...thread.participantIds],
    envelopes: thread.envelopes.filter((envelope) => envelope.toUserId === userId).sort(sortByDateAscending),
    messages: [...thread.messages]
      .map((message) => ({
        ...message,
        counter: message.counter ?? null,
        epoch: message.epoch ?? null,
        groupCommit: message.groupCommit
          ? {
              ...message.groupCommit,
              addedIds: [...message.groupCommit.addedIds],
              envelopes: message.groupCommit.envelopes.filter((envelope) => envelope.toUserId === userId),
              participantIds: [...message.groupCommit.participantIds],
              removedIds: [...message.groupCommit.removedIds],
            }
          : null,
        messageKind: message.messageKind ?? null,
        paddingBucket: message.paddingBucket ?? null,
        protocol: message.protocol ?? thread.protocol ?? "static-room-v1",
        ratchetPublicJwk: message.ratchetPublicJwk ?? null,
        threadId: message.threadId ?? thread.id,
        wireMessage: message.wireMessage ?? null,
      }))
      .sort(sortByDateAscending),
  };
}

function invalidateUserEphemeralState(userId) {
  for (const [token, session] of SESSION_CAPABILITIES.entries()) {
    if (session?.userId === userId) {
      SESSION_CAPABILITIES.delete(token);
    }
  }

  for (const [handle, record] of CONTACT_HANDLES.entries()) {
    if (record?.viewerUserId === userId || record?.targetUserId === userId) {
      CONTACT_HANDLES.delete(handle);
      CONTACT_HANDLE_INDEX.delete(`${record?.viewerUserId ?? ""}:${record?.targetUserId ?? ""}`);
    }
  }

  for (const [token, record] of MAILBOX_CAPABILITIES.entries()) {
    if (record?.userId === userId) {
      MAILBOX_CAPABILITIES.delete(token);
      MAILBOX_CAPABILITY_INDEX.delete(`${record?.threadId ?? ""}:${record?.userId ?? ""}`);
    }
  }
}

function invalidateDeviceSessionCapabilities(userId, deviceId) {
  if (!isNonEmptyString(userId, 120) || !isNonEmptyString(deviceId, 120)) {
    return;
  }

  for (const [token, session] of SESSION_CAPABILITIES.entries()) {
    if (session?.userId === userId && session?.deviceId === deviceId) {
      SESSION_CAPABILITIES.delete(token);
    }
  }
}

function invalidateUserMailboxCapabilities(userId) {
  if (!isNonEmptyString(userId, 120)) {
    return;
  }

  for (const [token, record] of MAILBOX_CAPABILITIES.entries()) {
    if (record?.userId === userId) {
      MAILBOX_CAPABILITIES.delete(token);
      MAILBOX_CAPABILITY_INDEX.delete(`${record?.threadId ?? ""}:${record?.userId ?? ""}`);
    }
  }
}

function deactivateUserAccount(user, now) {
  const priorUsername = user.username;
  const tombstoneUsername = `deleted-${user.id.slice(0, 8)}`;
  user.deactivatedAt = now;
  user.directoryCode = null;
  user.displayName = "Deleted user";
  user.mlsKeyPackage = null;
  user.prekeyCreatedAt = null;
  user.prekeyFingerprint = null;
  user.prekeyPublicJwk = null;
  user.prekeySignature = null;
  user.signalBundle = null;
  user.signalBundleDigest = null;
  user.updatedAt = now;
  user.username = tombstoneUsername;
  user.devices = Array.isArray(user.devices)
    ? user.devices.map((device) => ({
        ...device,
        revokedAt: device.revokedAt ?? now,
        updatedAt: now,
      }))
    : [];
  user.deviceEvents = Array.isArray(user.deviceEvents)
    ? user.deviceEvents
    : [];
  recordDeviceEvent(user, {
    actorDeviceId: null,
    createdAt: now,
    deviceId: null,
    kind: "account-deactivated",
    label: priorUsername,
    platform: null,
    revokedAt: now,
  });
  invalidateUserEphemeralState(user.id);
  return {
    priorUsername,
    tombstoneUsername,
  };
}

function publicTransparencyState() {
  const statement = signedTransparencyState();
  return {
    entryCount: store.transparencyLog.length,
    relayTime: new Date().toISOString(),
    transparencySignature: statement.signature,
    transparencySigner: statement.signer,
    transparencyEntries: store.transparencyLog.map(publicTransparencyEntry),
    transparencyHead: store.transparencyHead,
  };
}

function sessionBucketKey(session, suffix = "session") {
  return privacyPreservingRateLimitKey(`${session.sessionId ?? session.userId}:${suffix}`);
}

function mailboxBucketKey(capability, suffix = "mailbox") {
  return privacyPreservingRateLimitKey(`${capability.threadId}:${capability.userId}:${suffix}`);
}

function userBucketKey(userId, suffix = "user") {
  return privacyScopedBucketKey(`user:${suffix}`, userId);
}

function scopedUsersFor(userId) {
  return relatedUserIdsFor(userId)
    .map((relatedUserId) => store.users[relatedUserId])
    .filter(Boolean)
    .sort((left, right) => left.username.localeCompare(right.username))
    .map((user) => publicUserRecord(user, { viewerUserId: userId }));
}

function scopedThreadsFor(userId) {
  return Object.values(store.threads)
    .filter((thread) => thread.participantIds.includes(userId))
    .sort((left, right) => {
      const leftNewest = left.messages[left.messages.length - 1]?.createdAt ?? left.createdAt;
      const rightNewest = right.messages[right.messages.length - 1]?.createdAt ?? right.createdAt;
      return new Date(rightNewest).getTime() - new Date(leftNewest).getTime();
    })
    .map((thread) => sanitizeThreadForUser(thread, userId));
}

function publicDeviceSnapshot(userId, currentDeviceId = null) {
  const user = store.users[userId];
  if (!user) {
    return {
      deviceEvents: [],
      devices: [],
    };
  }

  return {
    deviceEvents: (user.deviceEvents ?? []).map((event) => publicDeviceEventRecord(event)),
    devices: (user.devices ?? []).map((device) => publicDeviceRecord(device, { currentDeviceId })),
  };
}

function sendSseEvent(response, eventName, payload) {
  response.write(`event: ${eventName}\n`);
  response.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function broadcastSync(userIds, reason, threadId = null) {
  const timestamp = new Date().toISOString();

  for (const userId of new Set(userIds)) {
    const listeners = SSE_CLIENTS.get(userId);

    if (!listeners) {
      continue;
    }

    for (const response of listeners) {
      sendSseEvent(response, "sync", {
        reason,
        threadId,
        timestamp,
      });
    }
  }
}

function handleSse(request, response, url) {
  const userId = url.searchParams.get("userId");
  const ip = privacyPreservingRateLimitKey(getRequestIp(request));

  if (!isNonEmptyString(userId, 120) || !store.users[userId]) {
    sendError(request, response, 400, "A known userId is required to open the event stream.");
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.eventsPerIp, key: ip, scope: "events-ip" },
      ],
      "Event stream"
    )
  ) {
    return;
  }

  setApiHeaders(request, response);
  response.writeHead(200, {
    "Cache-Control": "no-store",
    Connection: "keep-alive",
    "Content-Type": "text/event-stream; charset=utf-8",
  });

  let listeners = SSE_CLIENTS.get(userId);
  if (!listeners) {
    listeners = new Set();
    SSE_CLIENTS.set(userId, listeners);
  }

  listeners.add(response);
  sendSseEvent(response, "hello", {
    timestamp: new Date().toISOString(),
  });

  request.on("close", () => {
    listeners.delete(response);

    if (listeners.size === 0) {
      SSE_CLIENTS.delete(userId);
    }
  });
}

async function handleRegister(request, response) {
  const ip = privacyPreservingRateLimitKey(getRequestIp(request));
  const instanceKey = getRequestInstanceKey(request);
  const requestDeviceId = getRequestDeviceId(request);
  const rawIntegrityObservation = parseIntegrityReportHeader(request);
  const integrityObservation = sanitizeIntegrityObservation(rawIntegrityObservation);
  const integrityProofTokens = sanitizeIntegrityProofTokens(rawIntegrityObservation);

  if (!requireProofOfWork(request, response, "register", integrityObservation)) {
    return;
  }

  const body = await readJsonBody(request);
  const username = isNonEmptyString(body.username, 30) ? normalizeUsername(body.username) : "";
  const displayName = isNonEmptyString(body.displayName, 60) ? body.displayName.trim() : "";
  const requestedUserId = isNonEmptyString(body.userId, 120) ? body.userId.trim() : null;
  const fingerprint = isNonEmptyString(body.fingerprint, 120) ? body.fingerprint.trim() : "";
  const prekeyCreatedAt = isNonEmptyString(body.prekeyCreatedAt, 60) ? body.prekeyCreatedAt.trim() : null;
  const prekeyFingerprint = isNonEmptyString(body.prekeyFingerprint, 120) ? body.prekeyFingerprint.trim() : null;
  const prekeySignature = isNonEmptyString(body.prekeySignature, 20_000) ? body.prekeySignature.trim() : null;
  const recoveryFingerprint = isNonEmptyString(body.recoveryFingerprint, 120) ? body.recoveryFingerprint.trim() : "";
  const deviceEnrollment = body.device ? sanitizeDeviceEnrollment(body.device) : null;
  const deviceAttestation = body.device ? sanitizeDeviceAttestationPayload(body.device.attestation) : null;

  if (!/^[a-z0-9._-]{3,24}$/.test(username)) {
    sendError(request, response, 400, "Username must be 3-24 characters using lowercase letters, numbers, dots, dashes, or underscores.");
    return;
  }

  if (!displayName) {
    sendError(request, response, 400, "Display name is required.");
    return;
  }

  if (!fingerprint) {
    sendError(request, response, 400, "Fingerprint is required.");
    return;
  }

  if (!recoveryFingerprint) {
    sendError(request, response, 400, "Recovery fingerprint is required.");
    return;
  }

  if (!ensurePublicJwk(body.signingPublicJwk) || !ensurePublicJwk(body.encryptionPublicJwk)) {
    sendError(request, response, 400, "Public signing and encryption keys are required.");
    return;
  }

  const existingByUsername = Object.values(store.users).find((user) => user.username === username);
  const existingById = requestedUserId ? store.users[requestedUserId] : null;
  const isExistingMatchingRegistration =
    (existingById && storedAccountMatchesRegistration(existingById, body, { username, fingerprint, recoveryFingerprint })) ||
    (existingByUsername &&
      storedAccountMatchesRegistration(existingByUsername, body, {
        username,
        fingerprint,
        recoveryFingerprint,
      }));

  const registerLimits = isExistingMatchingRegistration
    ? [
        { config: RATE_LIMITS.registerRefreshPerIp, key: ip, scope: "register-refresh-ip" },
        ...(instanceKey
          ? [{ config: RATE_LIMITS.registerRefreshPerInstance, key: instanceKey, scope: "register-refresh-instance" }]
          : []),
      ]
    : [
        { config: RATE_LIMITS.registerPerIp, key: ip, scope: "register-ip" },
        ...(instanceKey ? [{ config: RATE_LIMITS.registerPerInstance, key: instanceKey, scope: "register-instance" }] : []),
      ];

  if (!enforceRateLimits(request, response, registerLimits, isExistingMatchingRegistration ? "Registration refresh" : "Registration")) {
    return;
  }

  if (body.device && !deviceEnrollment) {
    sendError(request, response, 400, "Linked-device registrations must include a valid device descriptor.");
    return;
  }

  if (requestDeviceId && deviceEnrollment && requestDeviceId !== deviceEnrollment.id) {
    sendError(request, response, 400, "The device header did not match the signed device descriptor.");
    return;
  }

  if (!ensurePublicJwk(body.recoveryPublicJwk)) {
    sendError(request, response, 400, "A recovery public key is required for account reset and lost-device recovery.");
    return;
  }

  if (body.prekeyPublicJwk && !ensurePublicJwk(body.prekeyPublicJwk)) {
    sendError(request, response, 400, "Signed prekeys must be valid ECDH public JWK objects.");
    return;
  }

  if (body.signalBundle && !sanitizeSignalBundle(body.signalBundle)) {
    sendError(request, response, 400, "Signal bundles must include valid PQXDH public key material.");
    return;
  }

  if (body.mlsKeyPackage && !sanitizeMlsKeyPackage(body.mlsKeyPackage)) {
    sendError(request, response, 400, "MLS key packages must include a valid ciphersuite label and serialized key package.");
    return;
  }

  const verificationSummaries = [];
  if (deviceEnrollment?.platform === "android") {
    const androidKeyAttestationSummary = await verifyAndroidAttestationWithService(deviceAttestation);
    if (androidKeyAttestationSummary) {
      verificationSummaries.push(androidKeyAttestationSummary);
    }

    if (REQUIRE_ANDROID_ATTESTATION && androidKeyAttestationSummary?.verified !== true) {
      sendError(
        request,
        response,
        403,
        androidKeyAttestationSummary?.note ?? "Android registrations on this relay must pass separate attestation verification."
      );
      return;
    }

    const playIntegritySummary = await verifyAndroidPlayIntegrityWithService({
      bundleIdentifier: integrityObservation?.bundleIdentifier ?? null,
      deviceId: deviceEnrollment.id,
      generatedAt: integrityObservation?.generatedAt ?? null,
      playIntegrityToken: integrityProofTokens?.playIntegrityToken ?? null,
    });
    if (playIntegritySummary) {
      verificationSummaries.push(playIntegritySummary);
    }

    if (REQUIRE_ANDROID_PLAY_INTEGRITY && playIntegritySummary?.verified !== true) {
      sendError(
        request,
        response,
        403,
        playIntegritySummary?.note ?? "Android registrations on this relay must pass Play Integrity verification."
      );
      return;
    }
  }

  if (deviceEnrollment?.platform === "macos") {
    const deviceCheckSummary = await verifyAppleDeviceCheckWithService({
      bundleIdentifier: integrityObservation?.bundleIdentifier ?? null,
      deviceCheckToken: integrityProofTokens?.deviceCheckToken ?? null,
      deviceId: deviceEnrollment.id,
      generatedAt: integrityObservation?.generatedAt ?? null,
    });
    if (deviceCheckSummary) {
      verificationSummaries.push(deviceCheckSummary);
    }

    if (REQUIRE_APPLE_DEVICECHECK && deviceCheckSummary?.verified !== true) {
      sendError(
        request,
        response,
        403,
        deviceCheckSummary?.note ?? "macOS registrations on this relay must pass DeviceCheck verification."
      );
      return;
    }
  }

  const attestationSummary = mergeVerificationSummaries(verificationSummaries);

  const now = new Date().toISOString();
  let userRecord = null;
  let appendTransparency = null;

  if (existingById) {
    if (
      existingById.username !== username ||
      existingById.fingerprint !== fingerprint ||
      existingById.recoveryFingerprint !== recoveryFingerprint ||
      !publicJwksEqual(existingById.signingPublicJwk, body.signingPublicJwk) ||
      !publicJwksEqual(existingById.encryptionPublicJwk, body.encryptionPublicJwk) ||
      !publicJwksEqual(existingById.recoveryPublicJwk, body.recoveryPublicJwk)
    ) {
      sendError(request, response, 409, "That device identity does not match the stored account record.");
      return;
    }

    existingById.displayName = displayName;
    if (
      body.prekeyPublicJwk &&
      !publicJwksEqual(existingById.prekeyPublicJwk, body.prekeyPublicJwk)
    ) {
      existingById.prekeyCreatedAt = prekeyCreatedAt;
      existingById.prekeyFingerprint = prekeyFingerprint;
      existingById.prekeyPublicJwk = normalizePublicJwk(body.prekeyPublicJwk);
      existingById.prekeySignature = prekeySignature;
      appendTransparency = {
        createdAt: now,
        fingerprint,
        kind: "prekey-rotation",
        prekeyFingerprint,
        userId: existingById.id,
        username,
      };
    }
    existingById.signalBundle = sanitizeSignalBundle(body.signalBundle) ?? existingById.signalBundle ?? null;
    const nextSignalBundleDigest = signalBundleDigest(body.signalBundle);
    if (nextSignalBundleDigest && nextSignalBundleDigest !== existingById.signalBundleDigest) {
      existingById.signalBundleDigest = nextSignalBundleDigest;
      appendTransparency = {
        createdAt: now,
        fingerprint,
        kind: "signal-prekey-rotation",
        prekeyFingerprint,
        userId: existingById.id,
        username,
      };
    }
    existingById.mlsKeyPackage = sanitizeMlsKeyPackage(body.mlsKeyPackage) ?? existingById.mlsKeyPackage ?? null;
    existingById.integrityObservation = integrityObservation ?? existingById.integrityObservation ?? null;
    existingById.updatedAt = now;
    const deviceUpsert = upsertUserDevice(existingById, deviceEnrollment, {
      actorDeviceId: deviceEnrollment?.id ?? null,
      attestationSummary,
      integrityObservation,
      now,
    });
    if (deviceUpsert?.error) {
      sendError(request, response, 403, deviceUpsert.error);
      return;
    }
    userRecord = existingById;
  } else if (existingByUsername) {
    if (
      existingByUsername.fingerprint !== fingerprint ||
      existingByUsername.recoveryFingerprint !== recoveryFingerprint ||
      !publicJwksEqual(existingByUsername.signingPublicJwk, body.signingPublicJwk) ||
      !publicJwksEqual(existingByUsername.encryptionPublicJwk, body.encryptionPublicJwk) ||
      !publicJwksEqual(existingByUsername.recoveryPublicJwk, body.recoveryPublicJwk)
    ) {
      sendError(request, response, 409, "That username is already bound to a different device identity.");
      return;
    }

    existingByUsername.displayName = displayName;
    if (
      body.prekeyPublicJwk &&
      !publicJwksEqual(existingByUsername.prekeyPublicJwk, body.prekeyPublicJwk)
    ) {
      existingByUsername.prekeyCreatedAt = prekeyCreatedAt;
      existingByUsername.prekeyFingerprint = prekeyFingerprint;
      existingByUsername.prekeyPublicJwk = normalizePublicJwk(body.prekeyPublicJwk);
      existingByUsername.prekeySignature = prekeySignature;
      appendTransparency = {
        createdAt: now,
        fingerprint,
        kind: "prekey-rotation",
        prekeyFingerprint,
        userId: existingByUsername.id,
        username,
      };
    }
    existingByUsername.signalBundle = sanitizeSignalBundle(body.signalBundle) ?? existingByUsername.signalBundle ?? null;
    const nextSignalBundleDigest = signalBundleDigest(body.signalBundle);
    if (nextSignalBundleDigest && nextSignalBundleDigest !== existingByUsername.signalBundleDigest) {
      existingByUsername.signalBundleDigest = nextSignalBundleDigest;
      appendTransparency = {
        createdAt: now,
        fingerprint,
        kind: "signal-prekey-rotation",
        prekeyFingerprint,
        userId: existingByUsername.id,
        username,
      };
    }
    existingByUsername.mlsKeyPackage = sanitizeMlsKeyPackage(body.mlsKeyPackage) ?? existingByUsername.mlsKeyPackage ?? null;
    existingByUsername.integrityObservation = integrityObservation ?? existingByUsername.integrityObservation ?? null;
    existingByUsername.updatedAt = now;
    const deviceUpsert = upsertUserDevice(existingByUsername, deviceEnrollment, {
      actorDeviceId: deviceEnrollment?.id ?? null,
      attestationSummary,
      integrityObservation,
      now,
    });
    if (deviceUpsert?.error) {
      sendError(request, response, 403, deviceUpsert.error);
      return;
    }
    userRecord = existingByUsername;
  } else {
    const userId = requestedUserId ?? randomUUID();
    userRecord = {
      id: userId,
      username,
      displayName,
      directoryCode: generateDirectoryCode(),
      fingerprint,
      integrityObservation,
      mlsKeyPackage: sanitizeMlsKeyPackage(body.mlsKeyPackage),
      prekeyCreatedAt,
      prekeyFingerprint,
      prekeyPublicJwk: normalizePublicJwk(body.prekeyPublicJwk),
      prekeySignature,
      recoveryFingerprint,
      recoveryPublicJwk: normalizePublicJwk(body.recoveryPublicJwk),
      signalBundle: sanitizeSignalBundle(body.signalBundle),
      signalBundleDigest: signalBundleDigest(body.signalBundle),
      signingPublicJwk: normalizePublicJwk(body.signingPublicJwk),
      encryptionPublicJwk: normalizePublicJwk(body.encryptionPublicJwk),
      deviceEvents: [],
      devices: [],
      createdAt: now,
      updatedAt: now,
    };
    const deviceUpsert = upsertUserDevice(userRecord, deviceEnrollment, {
      actorDeviceId: deviceEnrollment?.id ?? null,
      attestationSummary,
      integrityObservation,
      now,
    });
    if (deviceUpsert?.error) {
      sendError(request, response, 403, deviceUpsert.error);
      return;
    }
    store.users[userId] = userRecord;
    appendTransparency = {
      createdAt: now,
      fingerprint,
      kind: "identity-created",
      prekeyFingerprint,
      userId,
      username,
    };
  }

  if (appendTransparency) {
    appendTransparencyEntry(appendTransparency);
  }

  await queuePersist();
  const session = issueSessionCapability({
    deviceId: deviceEnrollment?.id ?? requestDeviceId ?? null,
    integrityObservation,
    userId: userRecord.id,
  });
  sendJson(request, response, 200, {
    privacyMode: "opaque-routing-v1",
    session,
    user: publicUserRecord(userRecord, { viewerUserId: userRecord.id }),
    deviceEvents: (userRecord.deviceEvents ?? []).map((event) => publicDeviceEventRecord(event)),
    devices: (userRecord.devices ?? []).map((device) =>
      publicDeviceRecord(device, { currentDeviceId: deviceEnrollment?.id ?? requestDeviceId ?? null })
    ),
  });
}

async function handleSync(request, response, url) {
  const userId = url.searchParams.get("userId");
  const ip = privacyPreservingRateLimitKey(getRequestIp(request));
  const requestDeviceId = getRequestDeviceId(request);
  const integrityObservation = sanitizeIntegrityObservation(parseIntegrityReportHeader(request));

  pruneExpiredArtifacts();

  if (!isNonEmptyString(userId, 120) || !store.users[userId]) {
    sendError(request, response, 404, "Unknown user.");
    return;
  }

  if (requestDeviceId) {
    const device = findUserDevice(store.users[userId], requestDeviceId);
    if (!device) {
      sendError(request, response, 403, "That device is not linked to this account.");
      return;
    }
    if (device.revokedAt) {
      sendError(request, response, 403, "That linked device has been revoked.");
      return;
    }
    device.updatedAt = new Date().toISOString();
    if (integrityObservation?.riskLevel) {
      device.riskLevel = integrityObservation.riskLevel;
    }
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [{ config: RATE_LIMITS.syncPerIp, key: ip, scope: "sync-ip" }],
      "Sync"
    )
  ) {
    return;
  }

  if (integrityObservation) {
    store.users[userId].integrityObservation = integrityObservation;
    store.users[userId].updatedAt = new Date().toISOString();
    await queuePersist();
  }

  const threads = Object.values(store.threads)
    .filter((thread) => thread.participantIds.includes(userId))
    .sort((left, right) => {
      const leftNewest = left.messages[left.messages.length - 1]?.createdAt ?? left.createdAt;
      const rightNewest = right.messages[right.messages.length - 1]?.createdAt ?? right.createdAt;
      return new Date(rightNewest).getTime() - new Date(leftNewest).getTime();
    })
    .map((thread) => sanitizeThreadForUser(thread, userId));

  const users = relatedUserIdsFor(userId)
    .map((relatedUserId) => store.users[relatedUserId])
    .filter(Boolean)
    .sort((left, right) => left.username.localeCompare(right.username))
    .map((user) => publicUserRecord(user, { viewerUserId: userId }));

  sendJson(request, response, 200, {
    directoryDiscoveryMode: "username-or-invite",
    users,
    threads,
  });
}

async function handleDirectorySearch(request, response, url) {
  const userId = url.searchParams.get("userId");
  const query = url.searchParams.get("q");
  const ip = privacyPreservingRateLimitKey(getRequestIp(request));
  const instanceKey = getRequestInstanceKey(request);
  const integrityObservation = sanitizeIntegrityObservation(parseIntegrityReportHeader(request));

  if (!isNonEmptyString(userId, 120) || !store.users[userId]) {
    sendError(request, response, 404, "Unknown user.");
    return;
  }

  if (!isNonEmptyString(query, 80)) {
    sendError(request, response, 400, "Directory search requires a query.");
    return;
  }

  const exactUsernameOrInviteOnly = ACTIVE_PROTOCOL_POLICY === "require-standards";
  if (!normalizeDirectoryCode(query) && query.trim().length < DIRECTORY_SEARCH_MIN_LENGTH) {
    sendError(request, response, 400, `Directory search requires at least ${DIRECTORY_SEARCH_MIN_LENGTH} characters.`);
    return;
  }

  if (!requireProofOfWork(request, response, "directory-search", integrityObservation)) {
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.searchPerIp, key: ip, scope: "search-ip" },
        ...(instanceKey ? [{ config: RATE_LIMITS.searchPerInstance, key: instanceKey, scope: "search-instance" }] : []),
      ],
      "Directory search"
    )
  ) {
    return;
  }

  sendJson(request, response, 200, {
    mode: "username-or-invite",
    results: searchDirectoryRecords(query, userId, { exactUsernameOrInviteOnly }),
  });
}

async function handleReportAbuse(request, response) {
  const session = requireSessionCapability(request, response);
  if (!session) {
    return;
  }

  const ip = privacyPreservingRateLimitKey(getRequestIp(request));
  const integrityObservation = sanitizeIntegrityObservation(parseIntegrityReportHeader(request));

  if (!requireProofOfWork(request, response, "report-abuse", integrityObservation)) {
    return;
  }

  const body = await readJsonBody(request);
  const reporterId = isNonEmptyString(body.reporterId, 120) ? body.reporterId.trim() : session.userId;
  const targetUserId = isNonEmptyString(body.targetUserId, 120) ? body.targetUserId.trim() : "";
  const createdAt = isNonEmptyString(body.createdAt, 60) ? body.createdAt.trim() : "";
  const reason = isNonEmptyString(body.reason, 80) ? body.reason.trim() : "";
  const threadId = isNonEmptyString(body.threadId, 160) ? body.threadId.trim() : null;
  const messageIds = dedupeStringArray(body.messageIds, 120).slice(0, 20);

  if (reporterId !== session.userId) {
    sendError(request, response, 403, "Reports must be submitted by the authenticated relay user.");
    return;
  }

  if (!store.users[reporterId]) {
    sendError(request, response, 404, "The reporting user is unknown.");
    return;
  }

  if (!targetUserId || !store.users[targetUserId]) {
    sendError(request, response, 404, "The reported user is unknown.");
    return;
  }

  if (!reason || !createdAt || Number.isNaN(new Date(createdAt).getTime())) {
    sendError(request, response, 400, "Reports must include a reason and valid timestamp.");
    return;
  }

  if (threadId) {
    const thread = store.threads[threadId];
    if (!thread) {
      sendError(request, response, 404, "The reported thread is unknown.");
      return;
    }
    if (!thread.participantIds.includes(reporterId) || !thread.participantIds.includes(targetUserId)) {
      sendError(request, response, 400, "Reports may only reference a shared thread between the reporter and target.");
      return;
    }
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.eventsPerIp, key: ip, scope: "report-ip" },
        { config: RATE_LIMITS.reportPerUser, key: userBucketKey(reporterId, "report"), scope: "report-user" },
      ],
      "Report submission"
    )
  ) {
    return;
  }

  const report = {
    id: randomUUID(),
    createdAt,
    messageIds,
    reason,
    reporterId,
    targetUserId,
    threadId,
  };

  store.reports.push(report);
  await queuePersist();
  sendJson(request, response, 200, { ok: true, reportId: report.id });
}

async function handleRevokeDevice(request, response) {
  const ip = privacyPreservingRateLimitKey(getRequestIp(request));
  const integrityObservation = sanitizeIntegrityObservation(parseIntegrityReportHeader(request));

  if (!requireProofOfWork(request, response, "report-abuse", integrityObservation)) {
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [{ config: RATE_LIMITS.eventsPerIp, key: ip, scope: "device-revoke-ip" }],
      "Device revocation"
    )
  ) {
    return;
  }

  const body = await readJsonBody(request);
  const userId = isNonEmptyString(body.userId, 120) ? body.userId.trim() : "";
  const signerDeviceId = isNonEmptyString(body.signerDeviceId, 120) ? body.signerDeviceId.trim() : "";
  const targetDeviceId = isNonEmptyString(body.targetDeviceId, 120) ? body.targetDeviceId.trim() : "";
  const createdAt = isNonEmptyString(body.createdAt, 60) ? body.createdAt.trim() : "";
  const signature = isNonEmptyString(body.signature, 20_000) ? body.signature.trim() : "";
  const user = store.users[userId];

  if (!user) {
    sendError(request, response, 404, "Unknown user.");
    return;
  }

  if (!signerDeviceId || !targetDeviceId || !createdAt || Number.isNaN(new Date(createdAt).getTime()) || !signature) {
    sendError(request, response, 400, "Device revocation requires a signer, target, timestamp, and signature.");
    return;
  }

  const signerDevice = findUserDevice(user, signerDeviceId);
  const targetDevice = findUserDevice(user, targetDeviceId);
  if (!signerDevice || signerDevice.revokedAt) {
    sendError(request, response, 403, "The signing device is not active on this account.");
    return;
  }

  if (!targetDevice || targetDevice.revokedAt) {
    sendError(request, response, 404, "The target device is not active on this account.");
    return;
  }

  const payload = deviceActionSignaturePayload({
    action: "device-revoke",
    createdAt,
    signerDeviceId,
    targetDeviceId,
    userId,
  });
  if (!verifyDeviceActionSignature({ device: signerDevice, signature, payload })) {
    sendError(request, response, 403, "The linked-device signature was invalid.");
    return;
  }

  const revokedAt = new Date().toISOString();
  targetDevice.revokedAt = revokedAt;
  targetDevice.updatedAt = revokedAt;
  invalidateDeviceSessionCapabilities(userId, targetDeviceId);
  invalidateUserMailboxCapabilities(userId);
  recordDeviceEvent(user, {
    actorDeviceId: signerDeviceId,
    createdAt: revokedAt,
    deviceId: targetDeviceId,
    kind: "device-revoked",
    label: targetDevice.label,
    platform: targetDevice.platform,
    revokedAt,
  });
  await queuePersist();
  broadcastSync([userId], "device-revoked", null);
  sendJson(request, response, 200, {
    deviceEvents: (user.deviceEvents ?? []).map((event) => publicDeviceEventRecord(event)),
    devices: (user.devices ?? []).map((device) => publicDeviceRecord(device, { currentDeviceId: signerDeviceId })),
    ok: true,
    revokedDeviceId: targetDeviceId,
  });
}

async function handleDeleteAccount(request, response) {
  const session = requireSessionCapability(request, response);
  if (!session) {
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [{ config: RATE_LIMITS.eventsPerIp, key: sessionBucketKey(session, "account-delete"), scope: "account-delete-v2" }],
      "Account deletion"
    )
  ) {
    return;
  }

  const user = store.users[session.userId];
  if (!user) {
    sendError(request, response, 404, "The current relay account is unknown.");
    return;
  }

  if (user.deactivatedAt) {
    sendJson(request, response, 200, {
      deletedUsername: user.username,
      ok: true,
      tombstoned: true,
      userId: user.id,
    });
    return;
  }

  const deletedAt = new Date().toISOString();
  const { priorUsername, tombstoneUsername } = deactivateUserAccount(user, deletedAt);
  await queuePersist();
  sendJson(request, response, 200, {
    deletedAt,
    deletedUsername: priorUsername,
    ok: true,
    tombstonedUsername: tombstoneUsername,
    userId: user.id,
  });
}

async function handleAccountReset(request, response) {
  const ip = privacyPreservingRateLimitKey(getRequestIp(request));
  const integrityObservation = sanitizeIntegrityObservation(parseIntegrityReportHeader(request));
  if (
    !enforceRateLimits(
      request,
      response,
      [{ config: RATE_LIMITS.registerPerIp, key: ip, scope: "account-reset-ip" }],
      "Account reset"
    )
  ) {
    return;
  }

  const body = await readJsonBody(request);
  const userId = isNonEmptyString(body.userId, 120) ? body.userId.trim() : "";
  const username = isNonEmptyString(body.username, 30) ? normalizeUsername(body.username) : "";
  const displayName = isNonEmptyString(body.displayName, 60) ? body.displayName.trim() : "";
  const fingerprint = isNonEmptyString(body.fingerprint, 120) ? body.fingerprint.trim() : "";
  const createdAt = isNonEmptyString(body.createdAt, 60) ? body.createdAt.trim() : "";
  const prekeyCreatedAt = isNonEmptyString(body.prekeyCreatedAt, 60) ? body.prekeyCreatedAt.trim() : null;
  const prekeyFingerprint = isNonEmptyString(body.prekeyFingerprint, 120) ? body.prekeyFingerprint.trim() : null;
  const prekeySignature = isNonEmptyString(body.prekeySignature, 20_000) ? body.prekeySignature.trim() : null;
  const recoveryFingerprint = isNonEmptyString(body.recoveryFingerprint, 120) ? body.recoveryFingerprint.trim() : "";
  const recoverySignature = isNonEmptyString(body.recoverySignature, 20_000) ? body.recoverySignature.trim() : "";
  const deviceEnrollment = body.device ? sanitizeDeviceEnrollment(body.device) : null;
  const existing = store.users[userId];

  if (!existing || existing.username !== username) {
    sendError(request, response, 404, "The requested account reset target is unknown.");
    return;
  }

  if (
    !displayName ||
    !fingerprint ||
    !createdAt ||
    Number.isNaN(new Date(createdAt).getTime()) ||
    !ensurePublicJwk(body.signingPublicJwk) ||
    !ensurePublicJwk(body.encryptionPublicJwk) ||
    !ensurePublicJwk(body.recoveryPublicJwk) ||
    !body.prekeyPublicJwk ||
    !ensurePublicJwk(body.prekeyPublicJwk) ||
    !recoveryFingerprint ||
    !recoverySignature
  ) {
    sendError(request, response, 400, "A recovery-authorized account reset must include complete replacement identity and prekey material.");
    return;
  }

  if (body.signalBundle && !sanitizeSignalBundle(body.signalBundle)) {
    sendError(request, response, 400, "Signal bundles must include valid PQXDH public key material.");
    return;
  }

  if (body.mlsKeyPackage && !sanitizeMlsKeyPackage(body.mlsKeyPackage)) {
    sendError(request, response, 400, "MLS key packages must include a valid ciphersuite label and serialized key package.");
    return;
  }

  if (
    existing.recoveryFingerprint !== recoveryFingerprint ||
    !publicJwksEqual(existing.recoveryPublicJwk, body.recoveryPublicJwk)
  ) {
    sendError(request, response, 403, "The recovery authority for this account did not match the stored recovery record.");
    return;
  }

  const payload = accountResetSignaturePayload({
    ...body,
    createdAt,
    displayName,
    fingerprint,
    prekeyCreatedAt,
    prekeyFingerprint,
    prekeySignature,
    recoveryFingerprint,
    recoverySignature,
    userId,
    username,
  });
  if (
    !verifyRecoverySignature({
      recoveryPublicJwk: body.recoveryPublicJwk,
      signature: recoverySignature,
      payload,
    })
  ) {
    sendError(request, response, 403, "The recovery signature for this account reset was invalid.");
    return;
  }

  existing.displayName = displayName;
  existing.fingerprint = fingerprint;
  existing.prekeyCreatedAt = prekeyCreatedAt;
  existing.prekeyFingerprint = prekeyFingerprint;
  existing.prekeyPublicJwk = normalizePublicJwk(body.prekeyPublicJwk);
  existing.prekeySignature = prekeySignature;
  existing.signalBundle = sanitizeSignalBundle(body.signalBundle);
  existing.signalBundleDigest = signalBundleDigest(body.signalBundle);
  existing.mlsKeyPackage = sanitizeMlsKeyPackage(body.mlsKeyPackage);
  existing.signingPublicJwk = normalizePublicJwk(body.signingPublicJwk);
  existing.encryptionPublicJwk = normalizePublicJwk(body.encryptionPublicJwk);
  existing.integrityObservation = integrityObservation ?? existing.integrityObservation ?? null;
  existing.updatedAt = new Date().toISOString();
  existing.devices = (existing.devices ?? []).map((device) => ({
    ...device,
    revokedAt: existing.updatedAt,
    updatedAt: existing.updatedAt,
  }));
  recordDeviceEvent(existing, {
    actorDeviceId: null,
    createdAt: existing.updatedAt,
    deviceId: "all-devices",
    kind: "account-reset",
    label: "All linked devices revoked",
    platform: null,
    revokedAt: existing.updatedAt,
  });
  const deviceUpsert = upsertUserDevice(existing, deviceEnrollment, {
    actorDeviceId: deviceEnrollment?.id ?? null,
    integrityObservation,
    now: existing.updatedAt,
  });
  if (deviceUpsert?.error) {
    sendError(request, response, 403, deviceUpsert.error);
    return;
  }

  appendTransparencyEntry({
    createdAt: existing.updatedAt,
    fingerprint,
    kind: "account-reset",
    prekeyFingerprint,
    userId,
    username,
  });

  await queuePersist();
  broadcastSync(Object.keys(store.users), "account-reset", null);
  const session = issueSessionCapability({
    deviceId: deviceEnrollment?.id ?? null,
    integrityObservation,
    userId: existing.id,
  });
  sendJson(request, response, 200, {
    ok: true,
    privacyMode: "opaque-routing-v1",
    session,
    user: publicUserRecord(existing, { viewerUserId: existing.id }),
  });
}

async function handleCreateThread(request, response, options = {}) {
  pruneExpiredArtifacts();
  const integrityObservation = sanitizeIntegrityObservation(parseIntegrityReportHeader(request));

  if (!options.skipProofOfWork && !requireProofOfWork(request, response, "create-thread", integrityObservation)) {
    return;
  }

  const body = options.body ?? await readJsonBody(request);
  const threadId = isNonEmptyString(body.id, 120) ? body.id.trim() : "";
  const createdAt = isNonEmptyString(body.createdAt, 60) ? body.createdAt.trim() : "";
  const title = isNonEmptyString(body.title, 90) ? body.title.trim() : "";
  const createdBy = options.actorUserId ?? (isNonEmptyString(body.createdBy, 120) ? body.createdBy.trim() : "");
  const protocol = isNonEmptyString(body.protocol, 40) ? body.protocol.trim() : "static-room-v1";
  const groupState = body.groupState ?? null;
  const initialRatchetPublicJwk = body.initialRatchetPublicJwk ?? null;
  const mlsBootstrap = body.mlsBootstrap ?? null;
  const participantIds = options.resolvedParticipantIds ?? dedupeStringArray(body.participantIds);
  const envelopes = Array.isArray(body.envelopes) ? body.envelopes : [];
  const protocolSpec = getProtocolSpec(protocol);

  if (!threadId || store.threads[threadId]) {
    sendError(request, response, 409, "Thread id is missing or already exists.");
    return;
  }

  if (!createdAt || Number.isNaN(new Date(createdAt).getTime())) {
    sendError(request, response, 400, "A valid createdAt timestamp is required.");
    return;
  }

  if (!store.users[createdBy]) {
    sendError(request, response, 404, "Thread creator is unknown.");
    return;
  }

  if (!ensureKnownProtocol(protocol) || !protocolSpec) {
    sendError(request, response, 400, `Unknown protocol "${protocol}".`);
    return;
  }

  if (!protocolAllowedUnderPolicy(protocol, ACTIVE_PROTOCOL_POLICY)) {
    const policy = protocolPolicySummary(ACTIVE_PROTOCOL_POLICY);
    sendJson(request, response, 412, {
      error: `${protocolSpec.label} is blocked by the active relay protocol policy.`,
      protocolPolicy: policy,
      protocolSpec: {
        label: protocolSpec.label,
        note: protocolSpec.note,
        productionReady: protocolSpec.productionReady,
        standardTrack: protocolSpec.standardTrack,
      },
    });
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.threadPerIp, key: privacyPreservingRateLimitKey(getRequestIp(request)), scope: "thread-ip" },
        { config: RATE_LIMITS.threadPerUser, key: userBucketKey(createdBy, "thread"), scope: "thread-user" },
      ],
      "Thread creation"
    )
  ) {
    return;
  }

  const dedupedParticipants = [...new Set(participantIds)];
  if (dedupedParticipants.length < 2 || !dedupedParticipants.includes(createdBy)) {
    sendError(request, response, 400, "Threads must include the creator and at least one other participant.");
    return;
  }

  if (dedupedParticipants.length > MAX_THREAD_PARTICIPANTS) {
    sendError(request, response, 400, `Threads may include at most ${MAX_THREAD_PARTICIPANTS} participants.`);
    return;
  }

  if (!dedupedParticipants.every((userId) => store.users[userId])) {
    sendError(request, response, 404, "One or more participants do not exist.");
    return;
  }

  if (protocol === "signal-pqxdh-double-ratchet-v1") {
    if (dedupedParticipants.length !== 2) {
      sendError(request, response, 400, "PQXDH + Double Ratchet direct threads require exactly two participants.");
      return;
    }
    if (envelopes.length > 0) {
      sendError(request, response, 400, "Signal direct threads must not include legacy room-key envelopes.");
      return;
    }
    if (initialRatchetPublicJwk || groupState || mlsBootstrap) {
      sendError(request, response, 400, "Signal direct threads may only include direct participant metadata and authenticated wire messages.");
      return;
    }
  } else if (protocol === "mls-rfc9420-v1") {
    if (dedupedParticipants.length < 3) {
      sendError(request, response, 400, "RFC 9420 MLS threads require three or more participants.");
      return;
    }
    if (envelopes.length > 0 || initialRatchetPublicJwk || groupState) {
      sendError(request, response, 400, "MLS threads must not include legacy room-key envelopes, group-tree metadata, or pairwise bootstrap keys.");
      return;
    }
  } else {
    if (envelopes.length !== dedupedParticipants.length) {
      sendError(request, response, 400, "A room-key envelope is required for each participant.");
      return;
    }
  }

  if (protocol === "pairwise-v2") {
    if (dedupedParticipants.length !== 2) {
      sendError(request, response, 400, "The pairwise ratchet protocol only supports direct two-person threads.");
      return;
    }

    if (!ensurePublicJwk(initialRatchetPublicJwk)) {
      sendError(request, response, 400, "Pairwise ratchet threads must include the creator's initial ratchet public key.");
      return;
    }
  }

  if ((protocol === "group-epoch-v2" || protocol === "group-tree-v3") && dedupedParticipants.length < 3) {
    sendError(
      request,
      response,
      400,
      protocol === "group-tree-v3"
        ? "The group tree protocol only supports threads with three or more participants."
        : "The group epoch ratchet protocol only supports threads with three or more participants."
    );
    return;
  }

  let sanitizedEnvelopes = [];
  let sanitizedGroupState = null;
  let sanitizedMlsBootstrap = null;

  if (protocol === "mls-rfc9420-v1") {
    sanitizedMlsBootstrap = sanitizeMlsBootstrap(mlsBootstrap, {
      creatorId: createdBy,
      participantIds: dedupedParticipants,
    });
    if (!sanitizedMlsBootstrap) {
      sendError(request, response, 400, "MLS threads must include valid welcome/bootstrap metadata for every non-creator participant.");
      return;
    }
  } else if (protocol === "signal-pqxdh-double-ratchet-v1") {
    sanitizedEnvelopes = [];
  } else {
    const expectedEnvelopeThreadId = protocol === "group-tree-v3" ? `${threadId}:epoch:1` : threadId;
    for (const envelope of envelopes) {
      const sanitized = sanitizeEnvelopeRecord(envelope, {
        allowedRecipients: dedupedParticipants,
        expectedFromUserId: createdBy,
        expectedThreadId: expectedEnvelopeThreadId,
      });
      if (!sanitized) {
        sendError(request, response, 400, "Every envelope must include signed ciphertext, sender, recipient, and timestamp fields.");
        return;
      }

      sanitizedEnvelopes.push(sanitized);
    }

    const uniqueRecipients = new Set(sanitizedEnvelopes.map((envelope) => envelope.toUserId));
    if (uniqueRecipients.size !== dedupedParticipants.length) {
      sendError(request, response, 400, "Each participant must receive exactly one room-key envelope.");
      return;
    }

    sanitizedGroupState = protocol === "group-tree-v3" ? sanitizeGroupState(groupState, dedupedParticipants) : null;
    if (protocol === "group-tree-v3" && !sanitizedGroupState) {
      sendError(request, response, 400, "Group tree threads must include valid signed tree state metadata.");
      return;
    }
  }

  store.threads[threadId] = {
    groupState: sanitizedGroupState,
    id: threadId,
    initialRatchetPublicJwk: protocol === "pairwise-v2" ? initialRatchetPublicJwk : null,
    mlsBootstrap: sanitizedMlsBootstrap,
    title: protocol === "signal-pqxdh-double-ratchet-v1" || protocol === "mls-rfc9420-v1" ? "" : title,
    protocol,
    createdAt,
    createdBy,
    participantIds: dedupedParticipants,
    envelopes: sanitizedEnvelopes.sort(sortByDateAscending),
    attachments: [],
    messages: [],
  };

  await queuePersist();
  broadcastSync(dedupedParticipants, "thread-created", threadId);
  sendJson(request, response, 201, { ok: true, threadId });
}

async function handlePostMessage(request, response, threadId, options = {}) {
  pruneExpiredArtifacts();
  const integrityObservation = sanitizeIntegrityObservation(parseIntegrityReportHeader(request));

  if (!options.skipProofOfWork && !requireProofOfWork(request, response, "post-message", integrityObservation)) {
    return;
  }

  const thread = store.threads[threadId];
  if (!thread) {
    sendError(request, response, 404, "Thread not found.");
    return;
  }

  const body = await readJsonBody(request);
  const messageId = isNonEmptyString(body.id, 120) ? body.id.trim() : "";
  const senderId = options.forcedSenderId ?? (isNonEmptyString(body.senderId, 120) ? body.senderId.trim() : "");
  const createdAt = isNonEmptyString(body.createdAt, 60) ? body.createdAt.trim() : "";
  const counter = typeof body.counter === "number" && Number.isInteger(body.counter) && body.counter >= 0 ? body.counter : null;
  const epoch = typeof body.epoch === "number" && Number.isInteger(body.epoch) && body.epoch >= 1 ? body.epoch : null;
  const groupCommit = body.groupCommit ?? null;
  const iv = isNonEmptyString(body.iv, 400) ? body.iv.trim() : "";
  const messageKind = isNonEmptyString(body.messageKind, 80) ? body.messageKind.trim() : "";
  const ciphertext = isNonEmptyString(body.ciphertext, 20_000) ? body.ciphertext.trim() : "";
  const paddingBucket =
    typeof body.paddingBucket === "number" && Number.isInteger(body.paddingBucket) && body.paddingBucket > 0
      ? body.paddingBucket
      : null;
  const protocol = isNonEmptyString(body.protocol, 40) ? body.protocol.trim() : thread.protocol ?? "static-room-v1";
  const protocolSpec = getProtocolSpec(protocol);
  const ratchetPublicJwk = body.ratchetPublicJwk ?? null;
  const signature = isNonEmptyString(body.signature, 20_000) ? body.signature.trim() : "";
  const wireMessage = isNonEmptyString(body.wireMessage, 400_000) ? body.wireMessage.trim() : "";

  if (!messageId || thread.messages.some((message) => message.id === messageId)) {
    sendError(request, response, 409, "Message id is missing or already exists in this thread.");
    return;
  }

  if (!thread.participantIds.includes(senderId)) {
    sendError(request, response, 403, "Only participants may post to this thread.");
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.messagePerIp, key: privacyPreservingRateLimitKey(getRequestIp(request)), scope: "message-ip" },
        { config: RATE_LIMITS.messagePerUser, key: userBucketKey(senderId, "message"), scope: "message-user" },
      ],
      "Message"
    )
  ) {
    return;
  }

  if (!createdAt || Number.isNaN(new Date(createdAt).getTime())) {
    sendError(request, response, 400, "A valid createdAt timestamp is required.");
    return;
  }

  if (!ensureKnownProtocol(protocol) || !protocolSpec) {
    sendError(request, response, 400, `Unknown protocol "${protocol}".`);
    return;
  }

  if (!protocolAllowedUnderPolicy(protocol, ACTIVE_PROTOCOL_POLICY)) {
    const policy = protocolPolicySummary(ACTIVE_PROTOCOL_POLICY);
    sendJson(request, response, 412, {
      error: `${protocolSpec.label} is blocked by the active relay protocol policy.`,
      protocolPolicy: policy,
      protocolSpec: {
        label: protocolSpec.label,
        note: protocolSpec.note,
        productionReady: protocolSpec.productionReady,
        standardTrack: protocolSpec.standardTrack,
      },
      threadId,
    });
    return;
  }

  const isStandardsSignal = protocol === "signal-pqxdh-double-ratchet-v1";
  const isStandardsMls = protocol === "mls-rfc9420-v1";

  if (isStandardsSignal || isStandardsMls) {
    if (!wireMessage || !messageKind) {
      sendError(request, response, 400, "Standards-based messages require authenticated wireMessage and messageKind fields.");
      return;
    }
  } else if (!iv || !ciphertext || !signature) {
    sendError(request, response, 400, "Encrypted messages require iv, ciphertext, and signature fields.");
    return;
  }

  if (isStandardsSignal && !["signal-prekey", "signal-whisper"].includes(messageKind)) {
    sendError(request, response, 400, "Signal direct messages must declare a supported messageKind.");
    return;
  }

  if (isStandardsMls && messageKind !== "mls-application") {
    sendError(request, response, 400, "MLS messages must use the mls-application messageKind.");
    return;
  }

  if (protocol === "pairwise-v2" && counter === null) {
    sendError(request, response, 400, "Pairwise ratchet messages must include a non-negative counter.");
    return;
  }

  if (protocol === "group-epoch-v2" && (counter === null || epoch === null)) {
    sendError(request, response, 400, "Group epoch ratchet messages must include non-negative counters and epoch numbers.");
    return;
  }

  if (protocol === "group-tree-v3" && (counter === null || epoch === null)) {
    sendError(request, response, 400, "Group tree messages must include non-negative counters and epoch numbers.");
    return;
  }

  if (ratchetPublicJwk && !ensurePublicJwk(ratchetPublicJwk)) {
    sendError(request, response, 400, "Ratchet messages must include a valid ECDH public JWK when advertising a new sending chain.");
    return;
  }

  const sanitizedGroupCommit =
    protocol === "group-tree-v3"
      ? groupCommit
        ? sanitizeGroupCommit(groupCommit, { createdAt, senderId, threadId })
        : null
      : null;
  if (protocol === "group-tree-v3" && groupCommit && !sanitizedGroupCommit) {
    sendError(request, response, 400, "Group tree commit metadata is invalid.");
    return;
  }

  if (
    sanitizedGroupCommit &&
    !sanitizedGroupCommit.participantIds.every((participantId) => store.users[participantId])
  ) {
    sendError(request, response, 404, "One or more members in the committed group state do not exist.");
    return;
  }

  const previousParticipants = [...thread.participantIds];
  thread.messages.push({
    counter,
    ciphertext: ciphertext || null,
    epoch,
    groupCommit: sanitizedGroupCommit,
    id: messageId,
    iv: iv || null,
    messageKind: messageKind || null,
    paddingBucket,
    protocol,
    ratchetPublicJwk: ratchetPublicJwk ?? null,
    senderId,
    signature: signature || null,
    threadId,
    createdAt,
    wireMessage: wireMessage || null,
  });
  thread.messages.sort(sortByDateAscending);

  if (protocol === "group-tree-v3" && sanitizedGroupCommit) {
    thread.participantIds = [...sanitizedGroupCommit.participantIds];
    thread.envelopes = [...sanitizedGroupCommit.envelopes];
    thread.groupState = {
      epoch: sanitizedGroupCommit.epoch,
      participantIds: [...sanitizedGroupCommit.participantIds],
      transcriptHash: sanitizedGroupCommit.transcriptHash,
      treeHash: sanitizedGroupCommit.treeHash,
    };
  }

  await queuePersist();
  broadcastSync(
    [...new Set([...previousParticipants, ...thread.participantIds])],
    "message-posted",
    threadId
  );
  sendJson(request, response, 201, { ok: true, messageId });
}

async function handleUploadAttachment(request, response, threadId, options = {}) {
  pruneExpiredArtifacts();
  const integrityObservation = sanitizeIntegrityObservation(parseIntegrityReportHeader(request));

  if (!options.skipProofOfWork && !requireProofOfWork(request, response, "upload-attachment", integrityObservation)) {
    return;
  }

  const thread = store.threads[threadId];
  if (!thread) {
    sendError(request, response, 404, "Thread not found.");
    return;
  }

  const body = await readJsonBody(request);
  const senderId = options.forcedSenderId ?? (isNonEmptyString(body.senderId, 120) ? body.senderId.trim() : "");
  if (!thread.participantIds.includes(senderId)) {
    sendError(request, response, 403, "Only participants may upload attachments for this thread.");
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.messagePerIp, key: privacyPreservingRateLimitKey(getRequestIp(request)), scope: "attachment-ip" },
        { config: RATE_LIMITS.messagePerUser, key: userBucketKey(senderId, "attachment"), scope: "attachment-user" },
      ],
      "Attachment"
    )
  ) {
    return;
  }

  const attachment = sanitizeAttachmentRecord(body, { senderId, threadId });
  if (!attachment) {
    sendError(request, response, 400, "Encrypted attachments must include senderId, threadId, createdAt, iv, ciphertext, sha256, and byteLength.");
    return;
  }

  if (thread.attachments.some((existing) => existing.id === attachment.id)) {
    sendError(request, response, 409, "Attachment id already exists in this thread.");
    return;
  }

  thread.attachments.push(attachment);
  thread.attachments.sort(sortByDateAscending);

  await queuePersist();
  broadcastSync(thread.participantIds, "attachment-uploaded", threadId);
  sendJson(request, response, 201, { ok: true, attachmentId: attachment.id });
}

async function handleFetchAttachment(request, response, threadId, attachmentId, url, options = {}) {
  const thread = store.threads[threadId];
  if (!thread) {
    sendError(request, response, 404, "Thread not found.");
    return;
  }

  const userId = options.forcedUserId ?? url.searchParams.get("userId");
  if (!isNonEmptyString(userId, 120) || !thread.participantIds.includes(userId)) {
    sendError(request, response, 403, "Only thread participants may fetch encrypted attachments.");
    return;
  }

  const attachment = thread.attachments.find((entry) => entry.id === attachmentId);
  if (!attachment) {
    sendError(request, response, 404, "Encrypted attachment not found.");
    return;
  }

  sendJson(request, response, 200, attachment);
}

async function handlePrivacySync(request, response) {
  const session = requireSessionCapability(request, response);
  if (!session) {
    return;
  }

  pruneExpiredArtifacts();

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.syncPerIp, key: privacyPreservingRateLimitKey(getRequestIp(request)), scope: "sync-ip-v2" },
        { config: RATE_LIMITS.syncPerIp, key: sessionBucketKey(session, "sync"), scope: "sync-session-v2" },
      ],
      "Sync"
    )
  ) {
    return;
  }

  sendJson(request, response, 200, {
    directoryDiscoveryMode: "username-or-invite",
    threads: scopedThreadsFor(session.userId),
    users: scopedUsersFor(session.userId),
  });
}

async function handleSecurityTransparency(request, response) {
  const session = requireSessionCapability(request, response);
  if (!session) {
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [{ config: RATE_LIMITS.syncPerIp, key: sessionBucketKey(session, "transparency"), scope: "security-transparency-v2" }],
      "Transparency state"
    )
  ) {
    return;
  }

  sendJson(request, response, 200, publicTransparencyState());
}

async function handleSecurityDevices(request, response) {
  const session = requireSessionCapability(request, response);
  if (!session) {
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [{ config: RATE_LIMITS.eventsPerIp, key: sessionBucketKey(session, "devices"), scope: "security-devices-v2" }],
      "Security devices"
    )
  ) {
    return;
  }

  sendJson(request, response, 200, publicDeviceSnapshot(session.userId, session.deviceId));
}

async function handleDirectorySearchV2(request, response, url) {
  const session = requireSessionCapability(request, response);
  if (!session) {
    return;
  }

  const query = url.searchParams.get("q");
  if (!isNonEmptyString(query, 80)) {
    sendError(request, response, 400, "Directory search requires a query.");
    return;
  }

  if (!normalizeDirectoryCode(query) && query.trim().length < DIRECTORY_SEARCH_MIN_LENGTH) {
    sendError(request, response, 400, `Directory search requires at least ${DIRECTORY_SEARCH_MIN_LENGTH} characters.`);
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.searchPerIp, key: privacyPreservingRateLimitKey(getRequestIp(request)), scope: "search-ip-v2" },
        { config: RATE_LIMITS.searchPerInstance, key: sessionBucketKey(session, "search"), scope: "search-session-v2" },
      ],
      "Directory search"
    )
  ) {
    return;
  }

  sendJson(request, response, 200, {
    mode: "opaque-contact-handle-v1",
    results: searchDirectoryRecords(query, session.userId, { exactUsernameOrInviteOnly: ACTIVE_PROTOCOL_POLICY === "require-standards" }),
  });
}

async function handleCreateThreadV2(request, response) {
  const session = requireSessionCapability(request, response);
  if (!session) {
    return;
  }

  const body = await readJsonBody(request);
  const participantHandles = dedupeStringArray(body.participantHandles ?? []);
  const resolvedParticipantIds = [...new Set([
    session.userId,
    ...participantHandles
      .map((handle) => resolveContactHandle(handle, session.userId))
      .filter(Boolean),
  ])];

  if (resolvedParticipantIds.length < 2) {
    sendError(request, response, 400, "Thread creation requires at least one valid opaque contact handle.");
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.threadPerIp, key: privacyPreservingRateLimitKey(getRequestIp(request)), scope: "thread-ip-v2" },
        { config: RATE_LIMITS.threadPerUser, key: sessionBucketKey(session, "thread"), scope: "thread-session-v2" },
      ],
      "Thread creation"
    )
  ) {
    return;
  }

  await handleCreateThread(request, response, {
    actorUserId: session.userId,
    body,
    resolvedParticipantIds,
    skipProofOfWork: true,
  });
}

async function handlePostMailboxMessage(request, response, mailboxHandle) {
  const capability = requireMailboxCapability(request, response, mailboxHandle);
  if (!capability) {
    return;
  }

  if (
    !enforceRateLimits(
      request,
      response,
      [
        { config: RATE_LIMITS.messagePerIp, key: privacyPreservingRateLimitKey(getRequestIp(request)), scope: "message-ip-v2" },
        { config: RATE_LIMITS.messagePerUser, key: mailboxBucketKey(capability, "message"), scope: "message-capability-v2" },
      ],
      "Message"
    )
  ) {
    return;
  }

  await handlePostMessage(request, response, capability.threadId, {
    forcedSenderId: capability.userId,
    skipProofOfWork: true,
  });
}

async function handleUploadMailboxAttachment(request, response, mailboxHandle) {
  const capability = requireMailboxCapability(request, response, mailboxHandle);
  if (!capability) {
    return;
  }

  await handleUploadAttachment(request, response, capability.threadId, {
    forcedSenderId: capability.userId,
    skipProofOfWork: true,
  });
}

async function handleFetchMailboxAttachment(request, response, mailboxHandle, attachmentId, url) {
  const capability = requireMailboxCapability(request, response, mailboxHandle);
  if (!capability) {
    return;
  }

  await handleFetchAttachment(request, response, capability.threadId, attachmentId, url, {
    forcedUserId: capability.userId,
  });
}

async function requestListener(request, response) {
  try {
    const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);
    const { pathname } = url;

    if ((request.method === "GET" || request.method === "HEAD") && (await sendStaticAsset(request, response, pathname))) {
      return;
    }

    if (request.method === "OPTIONS" && (pathname === "/events" || pathname.startsWith("/api/"))) {
      setApiHeaders(request, response);
      response.writeHead(204, {
        "Cache-Control": "no-store",
      });
      response.end();
      return;
    }

    if (request.method === "GET" && pathname === "/api/health") {
      const protocolPolicy = protocolPolicySummary(ACTIVE_PROTOCOL_POLICY);
      const transparencyState = publicTransparencyState();
      sendJson(request, response, 200, {
        ok: true,
        clientOrigins: CLIENT_ORIGINS,
        protocolPolicy,
        transparency: {
          entryCount: transparencyState.entryCount,
          signer: transparencyState.transparencySigner,
        },
        transport: {
          remoteHttpAllowed: false,
          tls: HTTPS_KEY_FILE && HTTPS_CERT_FILE ? "tls1.3" : "localhost-http-only",
        },
        rateLimits: {
          messagePerIp: RATE_LIMITS.messagePerIp.limit,
          messagePerUser: RATE_LIMITS.messagePerUser.limit,
          registerPerIp: RATE_LIMITS.registerPerIp.limit,
          registerPerInstance: RATE_LIMITS.registerPerInstance.limit,
          registerRefreshPerIp: RATE_LIMITS.registerRefreshPerIp.limit,
          registerRefreshPerInstance: RATE_LIMITS.registerRefreshPerInstance.limit,
          reportPerUser: RATE_LIMITS.reportPerUser.limit,
          searchPerIp: RATE_LIMITS.searchPerIp.limit,
          searchPerInstance: RATE_LIMITS.searchPerInstance.limit,
          syncPerIp: RATE_LIMITS.syncPerIp.limit,
          threadPerIp: RATE_LIMITS.threadPerIp.limit,
          threadPerUser: RATE_LIMITS.threadPerUser.limit,
        },
        integritySignals: integrityRiskSummary(),
        attestation: {
          androidKeyAttestationRequired: REQUIRE_ANDROID_ATTESTATION,
          androidPlayIntegrityRequired: REQUIRE_ANDROID_PLAY_INTEGRITY,
          appleDeviceCheckRequired: REQUIRE_APPLE_DEVICECHECK,
          configured: Boolean(ATTESTATION_ORIGIN),
          required: REQUIRE_ANDROID_ATTESTATION,
        },
        abuseControls: {
          powDifficultyBits: POW_DIFFICULTY_BITS,
          powRequiredForRemoteUntrustedClients: true,
        },
        privacy: {
          legacyRoutesEnabled: ENABLE_LEGACY_API_ROUTES,
          mailboxRouting: "opaque-routing-v1",
          routineRequestShape: "capability-token + mailbox handle + encrypted blob",
          sessionBootstrap: "registration/bootstrap only",
        },
        directoryDiscoveryMode: "username-or-invite",
        users: Object.keys(store.users).length,
        threads: Object.keys(store.threads).length,
      });
      return;
    }

    if (request.method === "GET" && pathname === "/api/transparency") {
      sendJson(request, response, 200, publicTransparencyState());
      return;
    }

    if (request.method === "GET" && pathname === "/api/security/transparency") {
      await handleSecurityTransparency(request, response);
      return;
    }

    if (request.method === "GET" && pathname === "/api/security/devices") {
      await handleSecurityDevices(request, response);
      return;
    }

    if (request.method === "GET" && pathname === "/api/sync/state") {
      await handlePrivacySync(request, response);
      return;
    }

    if (request.method === "GET" && pathname === "/api/directory/search") {
      if (readAuthorizationToken(request)) {
        await handleDirectorySearchV2(request, response, url);
      } else {
        await handleDirectorySearch(request, response, url);
      }
      return;
    }

    if (request.method === "POST" && pathname === "/api/reports") {
      await handleReportAbuse(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/devices/revoke") {
      await handleRevokeDevice(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/account/delete") {
      await handleDeleteAccount(request, response);
      return;
    }

    if (request.method === "GET" && pathname === "/events") {
      handleSse(request, response, url);
      return;
    }

    if (request.method === "POST" && pathname === "/api/register") {
      await handleRegister(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/bootstrap/register") {
      await handleRegister(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/account-reset") {
      await handleAccountReset(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/bootstrap/account-reset") {
      await handleAccountReset(request, response);
      return;
    }

    if (request.method === "GET" && pathname === "/api/sync") {
      if (!ensureLegacyRouteEnabled(request, response, "/api/sync")) {
        return;
      }
      await handleSync(request, response, url);
      return;
    }

    if (request.method === "POST" && pathname === "/api/threads") {
      if (!ensureLegacyRouteEnabled(request, response, "/api/threads")) {
        return;
      }
      await handleCreateThread(request, response);
      return;
    }

    if (request.method === "POST" && pathname === "/api/routing/threads") {
      await handleCreateThreadV2(request, response);
      return;
    }

    const mailboxMessageMatch = pathname.match(/^\/api\/mailboxes\/([^/]+)\/messages$/);
    if (request.method === "POST" && mailboxMessageMatch) {
      await handlePostMailboxMessage(request, response, decodeURIComponent(mailboxMessageMatch[1]));
      return;
    }

    const mailboxAttachmentUploadMatch = pathname.match(/^\/api\/mailboxes\/([^/]+)\/attachments$/);
    if (request.method === "POST" && mailboxAttachmentUploadMatch) {
      await handleUploadMailboxAttachment(request, response, decodeURIComponent(mailboxAttachmentUploadMatch[1]));
      return;
    }

    const mailboxAttachmentFetchMatch = pathname.match(/^\/api\/mailboxes\/([^/]+)\/attachments\/([^/]+)$/);
    if (request.method === "GET" && mailboxAttachmentFetchMatch) {
      await handleFetchMailboxAttachment(
        request,
        response,
        decodeURIComponent(mailboxAttachmentFetchMatch[1]),
        decodeURIComponent(mailboxAttachmentFetchMatch[2]),
        url
      );
      return;
    }

    const threadMessageMatch = pathname.match(/^\/api\/threads\/([^/]+)\/messages$/);
    if (request.method === "POST" && threadMessageMatch) {
      await handlePostMessage(request, response, decodeURIComponent(threadMessageMatch[1]));
      return;
    }

    const threadAttachmentUploadMatch = pathname.match(/^\/api\/threads\/([^/]+)\/attachments$/);
    if (request.method === "POST" && threadAttachmentUploadMatch) {
      await handleUploadAttachment(request, response, decodeURIComponent(threadAttachmentUploadMatch[1]));
      return;
    }

    const threadAttachmentFetchMatch = pathname.match(/^\/api\/threads\/([^/]+)\/attachments\/([^/]+)$/);
    if (request.method === "GET" && threadAttachmentFetchMatch) {
      await handleFetchAttachment(
        request,
        response,
        decodeURIComponent(threadAttachmentFetchMatch[1]),
        decodeURIComponent(threadAttachmentFetchMatch[2]),
        url
      );
      return;
    }

    if (pathname.startsWith("/api/")) {
      sendError(request, response, 404, "Unknown API route.");
      return;
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      sendText(response, 405, "Method not allowed.");
      return;
    }

    sendText(response, 404, "Notrus Relay exposes API endpoints only. Use the native macOS or Android client.");
  } catch (error) {
    if (error instanceof SyntaxError) {
      sendError(request, response, 400, "Malformed JSON request body.");
      return;
    }

    console.error("Unhandled server error:", error);
    sendError(request, response, 500, "The relay hit an unexpected error.");
  }
}

async function createListeningServer() {
  if (HTTPS_KEY_FILE && HTTPS_CERT_FILE) {
    const [key, cert] = await Promise.all([
      fs.readFile(HTTPS_KEY_FILE),
      fs.readFile(HTTPS_CERT_FILE),
    ]);

    return {
      port: HTTPS_PORT,
      protocol: "https",
      server: https.createServer({ cert, key, minVersion: "TLSv1.3" }, requestListener),
    };
  }

  return {
    port: PORT,
    protocol: "http",
    server: http.createServer(requestListener),
  };
}

const { port: listeningPort, protocol, server } = await createListeningServer();

server.listen(listeningPort, HOST, () => {
  console.log(`Notrus Relay listening on ${protocol}://${HOST}:${listeningPort}`);
});

process.on("SIGINT", () => {
  server.close(() => process.exit(0));
});

process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
});
