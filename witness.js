import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WITNESS_UI_DIR = path.join(__dirname, "witness");
const DATA_DIR = process.env.WITNESS_DATA_DIR
  ? path.resolve(process.env.WITNESS_DATA_DIR)
  : path.join(__dirname, "data");
const STORE_PATH = process.env.WITNESS_STORE_PATH
  ? path.resolve(process.env.WITNESS_STORE_PATH)
  : path.join(DATA_DIR, "witness-store.json");
const PORT = Number(process.env.WITNESS_PORT || 3400);
const HOST = process.env.WITNESS_HOST || "127.0.0.1";
const RELAY_ORIGINS = (process.env.RELAY_ORIGINS ?? process.env.RELAY_ORIGIN ?? "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const POLL_INTERVAL_MS = Number(process.env.WITNESS_POLL_INTERVAL_MS || 15_000);
const MAX_HISTORY = Number(process.env.WITNESS_MAX_HISTORY || 256);
const ALLOW_ORIGINS = (process.env.WITNESS_ALLOW_ORIGINS ?? "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const WITNESS_ADMIN_TOKEN = (process.env.WITNESS_ADMIN_TOKEN ?? "").trim();
const WITNESS_ADMIN_HEADER = "x-notrus-witness-admin-token";
const STATIC_ROUTES = new Map([
  ["/", { contentType: "text/html; charset=utf-8", filePath: path.join(WITNESS_UI_DIR, "index.html") }],
  ["/witness", { contentType: "text/html; charset=utf-8", filePath: path.join(WITNESS_UI_DIR, "index.html") }],
  ["/witness/", { contentType: "text/html; charset=utf-8", filePath: path.join(WITNESS_UI_DIR, "index.html") }],
  ["/witness/app.js", { contentType: "text/javascript; charset=utf-8", filePath: path.join(WITNESS_UI_DIR, "app.js") }],
  ["/witness/styles.css", { contentType: "text/css; charset=utf-8", filePath: path.join(WITNESS_UI_DIR, "styles.css") }],
]);

let persistQueue = Promise.resolve();
let store = await loadStore();

function setApiHeaders(request, response) {
  response.setHeader("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Notrus-Witness-Admin-Token");
  response.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
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

async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function loadStore() {
  await ensureDataDir();

  try {
    const raw = await fs.readFile(STORE_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return {
      relays: parsed.relays ?? {},
    };
  } catch (error) {
    if (error.code === "ENOENT") {
      return { relays: {} };
    }

    throw error;
  }
}

function queuePersist() {
  const snapshot = JSON.stringify(store, null, 2);
  persistQueue = persistQueue.then(() => fs.writeFile(STORE_PATH, snapshot, "utf8"));
  return persistQueue;
}

function sendJson(request, response, statusCode, payload) {
  setApiHeaders(request, response);
  response.writeHead(statusCode);
  response.end(JSON.stringify(payload));
}

async function sendStaticAsset(request, response, pathname) {
  const asset = STATIC_ROUTES.get(pathname);
  if (!asset || request.method !== "GET") {
    return false;
  }

  try {
    const body = await fs.readFile(asset.filePath);
    response.writeHead(200, {
      "Cache-Control": asset.contentType.startsWith("text/html") ? "no-store" : "no-cache",
      "Content-Security-Policy": "default-src 'self'; connect-src 'self' https://relay.notrus.cloud https://witness.notrus.cloud; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
      "Content-Type": asset.contentType,
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(body);
    return true;
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.error("Witness static asset failed:", error.message);
    }
    return false;
  }
}

function safeEqualString(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeEqual(leftBuffer, rightBuffer);
}

function readWitnessAdminToken(request) {
  const headerToken = request.headers[WITNESS_ADMIN_HEADER];
  if (typeof headerToken === "string" && headerToken.trim()) {
    return headerToken.trim();
  }

  const authorization = request.headers.authorization;
  if (typeof authorization === "string" && authorization.startsWith("Bearer ")) {
    return authorization.slice("Bearer ".length).trim();
  }

  return "";
}

function hasWitnessAdminAccess(request) {
  if (!WITNESS_ADMIN_TOKEN) {
    return false;
  }
  const provided = readWitnessAdminToken(request);
  return Boolean(provided) && safeEqualString(provided, WITNESS_ADMIN_TOKEN);
}

function requireWitnessAdmin(request, response) {
  if (!WITNESS_ADMIN_TOKEN) {
    sendJson(request, response, 404, { error: "Witness read-only admin surface is disabled." });
    return false;
  }

  if (!hasWitnessAdminAccess(request)) {
    sendJson(request, response, 401, { error: "A valid witness read-only admin token is required." });
    return false;
  }

  return true;
}

function getRelayRecord(relayOrigin) {
  return store.relays[relayOrigin] ?? null;
}

function publicObservation(record) {
  if (!record) {
    return null;
  }

  return {
    entryCount: record.entryCount,
    observedAt: record.observedAt,
    relayOrigin: record.relayOrigin,
    transparencySignature: record.transparencySignature ?? null,
    transparencySigner: record.transparencySigner ?? null,
    transparencyHead: record.transparencyHead,
  };
}

function witnessLogPayload(relayOrigin) {
  const record = getRelayRecord(relayOrigin);
  return {
    history: record?.history ?? [],
    latest: publicObservation(record),
  };
}

function witnessAdminSnapshot() {
  return {
    maxHistory: MAX_HISTORY,
    pollIntervalMs: POLL_INTERVAL_MS,
    relays: Object.fromEntries(
      Object.entries(store.relays).map(([relayOrigin, record]) => [relayOrigin, publicObservation(record)])
    ),
    watching: RELAY_ORIGINS,
  };
}

function upsertObservation(relayOrigin, payload) {
  const history = store.relays[relayOrigin]?.history ?? [];
  const nextObservation = {
    entryCount: payload.entryCount,
    observedAt: new Date().toISOString(),
    relayOrigin,
    transparencySignature: payload.transparencySignature ?? null,
    transparencySigner: payload.transparencySigner ?? null,
    transparencyHead: payload.transparencyHead ?? null,
  };

  const previous = history[history.length - 1];
  if (
    previous &&
    previous.transparencyHead === nextObservation.transparencyHead &&
    previous.entryCount === nextObservation.entryCount &&
    JSON.stringify(previous.transparencySigner ?? null) === JSON.stringify(nextObservation.transparencySigner ?? null) &&
    previous.transparencySignature === nextObservation.transparencySignature
  ) {
    previous.observedAt = nextObservation.observedAt;
    store.relays[relayOrigin] = {
      entryCount: previous.entryCount,
      history,
      observedAt: previous.observedAt,
      relayOrigin,
      transparencySignature: previous.transparencySignature ?? null,
      transparencySigner: previous.transparencySigner ?? null,
      transparencyHead: previous.transparencyHead,
    };
    return false;
  }

  history.push(nextObservation);
  while (history.length > MAX_HISTORY) {
    history.shift();
  }

  store.relays[relayOrigin] = {
    ...nextObservation,
    history,
  };

  return true;
}

async function refreshRelay(relayOrigin) {
  const response = await fetch(new URL("/api/transparency", relayOrigin), {
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Witness poll failed with ${response.status}`);
  }

  const payload = await response.json();
  const changed = upsertObservation(relayOrigin, payload);
  if (changed) {
    await queuePersist();
  }
}

async function refreshAllRelays() {
  await Promise.all(
    RELAY_ORIGINS.map(async (relayOrigin) => {
      try {
        await refreshRelay(relayOrigin);
      } catch (error) {
        console.error(`Witness failed to observe ${relayOrigin}:`, error.message);
      }
    })
  );
}

export function createWitnessServer() {
  return http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);

      if (await sendStaticAsset(request, response, url.pathname)) {
        return;
      }

      if (request.method === "OPTIONS") {
        setApiHeaders(request, response);
        response.writeHead(204);
        response.end();
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/witness/health") {
        sendJson(request, response, 200, {
          admin: {
            enabled: Boolean(WITNESS_ADMIN_TOKEN),
            mode: WITNESS_ADMIN_TOKEN ? "read-only-token" : "disabled",
          },
          ok: true,
          relays: Object.keys(store.relays).length,
          watching: RELAY_ORIGINS,
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/witness/head") {
        const requestedRelayOrigin = url.searchParams.get("relayOrigin") || RELAY_ORIGINS[0] || "";
        if (!requestedRelayOrigin) {
          sendJson(request, response, 400, { error: "relayOrigin is required." });
          return;
        }

        const record = getRelayRecord(requestedRelayOrigin);
        sendJson(request, response, 200, {
          latest: publicObservation(record),
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/witness/log") {
        if (!requireWitnessAdmin(request, response)) {
          return;
        }

        const requestedRelayOrigin = url.searchParams.get("relayOrigin") || RELAY_ORIGINS[0] || "";
        if (!requestedRelayOrigin) {
          sendJson(request, response, 400, { error: "relayOrigin is required." });
          return;
        }

        sendJson(request, response, 200, witnessLogPayload(requestedRelayOrigin));
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/witness/admin/summary") {
        if (!requireWitnessAdmin(request, response)) {
          return;
        }
        sendJson(request, response, 200, witnessAdminSnapshot());
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/witness/admin/log") {
        if (!requireWitnessAdmin(request, response)) {
          return;
        }

        const requestedRelayOrigin = url.searchParams.get("relayOrigin") || RELAY_ORIGINS[0] || "";
        if (!requestedRelayOrigin) {
          sendJson(request, response, 400, { error: "relayOrigin is required." });
          return;
        }

        sendJson(request, response, 200, witnessLogPayload(requestedRelayOrigin));
        return;
      }

      sendJson(request, response, 404, { error: "Not found." });
    } catch (error) {
      console.error("Witness request failed:", error);
      sendJson(request, response, 500, { error: "Witness request failed." });
    }
  });
}

export async function primeWitnesses() {
  if (RELAY_ORIGINS.length > 0) {
    await refreshAllRelays();
  }
}

export function startWitnessServer({
  host = HOST,
  port = PORT,
} = {}) {
  const server = createWitnessServer();
  let pollHandle = null;
  server.listen(port, host, () => {
    console.log(`Notrus Witness listening on http://${host}:${port}`);
  });

  if (RELAY_ORIGINS.length > 0) {
    void refreshAllRelays();
    pollHandle = setInterval(() => {
      void refreshAllRelays();
    }, POLL_INTERVAL_MS);
    pollHandle.unref?.();
  }

  server.on("close", () => {
    if (pollHandle) {
      clearInterval(pollHandle);
      pollHandle = null;
    }
  });

  return server;
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file://").href) {
  startWitnessServer();
}
