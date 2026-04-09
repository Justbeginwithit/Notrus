import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
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

let persistQueue = Promise.resolve();
let store = await loadStore();

function setApiHeaders(request, response) {
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
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

      if (request.method === "OPTIONS") {
        setApiHeaders(request, response);
        response.writeHead(204);
        response.end();
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/witness/health") {
        sendJson(request, response, 200, {
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
        const requestedRelayOrigin = url.searchParams.get("relayOrigin") || RELAY_ORIGINS[0] || "";
        if (!requestedRelayOrigin) {
          sendJson(request, response, 400, { error: "relayOrigin is required." });
          return;
        }

        const record = getRelayRecord(requestedRelayOrigin);
        sendJson(request, response, 200, {
          history: record?.history ?? [],
          latest: publicObservation(record),
        });
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
