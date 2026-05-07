const DEFAULT_RELAY_ORIGIN = "https://relay.notrus.cloud";
const SESSION_KEYS = {
  relayOrigin: "notrus_witness_relay_origin",
  token: "notrus_witness_readonly_token",
  witnessOrigin: "notrus_witness_origin",
};

const els = {
  checksList: document.getElementById("checksList"),
  clearSession: document.getElementById("clearSession"),
  headBadge: document.getElementById("headBadge"),
  healthBadge: document.getElementById("healthBadge"),
  historyBody: document.getElementById("historyBody"),
  historyCount: document.getElementById("historyCount"),
  latestEntryCount: document.getElementById("latestEntryCount"),
  latestHead: document.getElementById("latestHead"),
  latestObservedAt: document.getElementById("latestObservedAt"),
  latestRelay: document.getElementById("latestRelay"),
  latestSignature: document.getElementById("latestSignature"),
  latestSigner: document.getElementById("latestSigner"),
  loadHistory: document.getElementById("loadHistory"),
  loadPublicHead: document.getElementById("loadPublicHead"),
  loadSummary: document.getElementById("loadSummary"),
  logBox: document.getElementById("logBox"),
  refreshAll: document.getElementById("refreshAll"),
  relayOriginInput: document.getElementById("relayOriginInput"),
  saveSession: document.getElementById("saveSession"),
  tokenBadge: document.getElementById("tokenBadge"),
  tokenInput: document.getElementById("tokenInput"),
  witnessOriginInput: document.getElementById("witnessOriginInput"),
};

function defaultWitnessOrigin() {
  const current = globalThis.location?.origin || "";
  return current.startsWith("http://") || current.startsWith("https://")
    ? current
    : "https://witness.notrus.cloud";
}

function normalizeOrigin(value, fallback) {
  const trimmed = (value || "").trim();
  if (!trimmed) {
    return fallback;
  }
  try {
    const url = new URL(trimmed);
    if (!["http:", "https:"].includes(url.protocol)) {
      return fallback;
    }
    url.username = "";
    url.password = "";
    url.pathname = "";
    url.search = "";
    url.hash = "";
    return `${url.protocol}//${url.host}`;
  } catch {
    return fallback;
  }
}

function config() {
  return {
    relayOrigin: normalizeOrigin(els.relayOriginInput.value, DEFAULT_RELAY_ORIGIN),
    token: els.tokenInput.value.trim(),
    witnessOrigin: normalizeOrigin(els.witnessOriginInput.value, defaultWitnessOrigin()),
  };
}

function log(message) {
  const prefix = `[${new Date().toISOString()}] `;
  els.logBox.textContent = `${prefix}${message}\n${els.logBox.textContent}`.slice(0, 12000);
}

function badge(element, text, kind) {
  element.textContent = text;
  element.className = `badge ${kind}`;
}

function short(value, length = 18) {
  if (!value) {
    return "-";
  }
  const text = String(value);
  return text.length > length ? `${text.slice(0, length)}...` : text;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function endpoint(path) {
  const cfg = config();
  const url = new URL(path, cfg.witnessOrigin);
  return { cfg, url };
}

async function requestJson(path, { token = "", allowFailure = false } = {}) {
  const { url } = endpoint(path);
  const headers = { Accept: "application/json" };
  if (token) {
    headers["X-Notrus-Witness-Admin-Token"] = token;
  }
  const response = await fetch(url, { headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok && !allowFailure) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }
  return { data, status: response.status };
}

function renderLatest(latest) {
  if (!latest) {
    badge(els.headBadge, "Relay head: missing", "warn");
    els.latestRelay.textContent = "-";
    els.latestEntryCount.textContent = "-";
    els.latestObservedAt.textContent = "-";
    els.latestSigner.textContent = "-";
    els.latestHead.textContent = "-";
    els.latestSignature.textContent = "-";
    renderChecks(null);
    return;
  }

  const signerId = latest.transparencySigner?.keyId || "";
  els.latestRelay.textContent = latest.relayOrigin || "-";
  els.latestEntryCount.textContent = String(latest.entryCount ?? "-");
  els.latestObservedAt.textContent = latest.observedAt || "-";
  els.latestSigner.textContent = signerId || "-";
  els.latestHead.textContent = latest.transparencyHead || "-";
  els.latestSignature.textContent = latest.transparencySignature ? "present" : "missing";
  badge(els.headBadge, `Relay head: ${latest.entryCount ?? "unknown"}`, latest.transparencySignature ? "ok" : "warn");
  renderChecks(latest);
}

function renderChecks(latest) {
  if (!latest) {
    els.checksList.innerHTML = '<li class="muted">No observation loaded yet.</li>';
    return;
  }

  const checks = [
    {
      ok: Number.isFinite(Number(latest.entryCount)),
      text: `Entry count is ${latest.entryCount ?? "missing"}.`,
    },
    {
      ok: Boolean(latest.transparencyHead),
      text: latest.transparencyHead ? "Transparency head is present." : "Transparency head is missing.",
    },
    {
      ok: Boolean(latest.transparencySignature),
      text: latest.transparencySignature ? "Relay signature is present." : "Relay signature is missing.",
    },
    {
      ok: Boolean(latest.transparencySigner?.keyId),
      text: latest.transparencySigner?.keyId
        ? `Signer key is ${latest.transparencySigner.keyId}.`
        : "Signer identity is missing.",
    },
    {
      ok: Boolean(latest.observedAt),
      text: latest.observedAt ? `Witness observed this at ${latest.observedAt}.` : "Observation time is missing.",
    },
  ];

  els.checksList.innerHTML = checks
    .map((check) => `<li class="${check.ok ? "ok-text" : "warn-text"}">${escapeHtml(check.text)}</li>`)
    .join("");
}

function renderHistory(history) {
  if (!Array.isArray(history) || history.length === 0) {
    els.historyBody.innerHTML = '<tr><td colspan="5" class="muted">No history available.</td></tr>';
    els.historyCount.textContent = "0 entries";
    return;
  }

  els.historyCount.textContent = `${history.length} entries`;
  els.historyBody.innerHTML = history
    .slice()
    .reverse()
    .map((entry) => `
      <tr>
        <td class="mono">${escapeHtml(entry.entryCount ?? "-")}</td>
        <td class="mono">${escapeHtml(entry.observedAt || "-")}</td>
        <td class="mono">${escapeHtml(entry.transparencySigner?.keyId || "-")}</td>
        <td class="mono break" title="${escapeHtml(entry.transparencyHead || "")}">${escapeHtml(short(entry.transparencyHead, 28))}</td>
        <td>${entry.transparencySignature ? '<span class="pill ok">present</span>' : '<span class="pill warn">missing</span>'}</td>
      </tr>
    `)
    .join("");
}

async function loadHealth() {
  const { data } = await requestJson("/api/witness/health");
  badge(els.healthBadge, `Witness: ${data.ok ? "ok" : "not ok"}`, data.ok ? "ok" : "warn");
  badge(
    els.tokenBadge,
    data.admin?.enabled ? "History: token protected" : "History: public or disabled",
    data.admin?.enabled ? "ok" : "muted"
  );
  log(`Witness health loaded. Watching ${Array.isArray(data.watching) ? data.watching.length : 0} relay origin(s).`);
  return data;
}

async function loadPublicHead() {
  const cfg = config();
  const query = new URLSearchParams({ relayOrigin: cfg.relayOrigin });
  const { data } = await requestJson(`/api/witness/head?${query.toString()}`);
  renderLatest(data.latest);
  log(`Public witness head loaded for ${cfg.relayOrigin}.`);
  return data.latest;
}

async function loadHistory() {
  const cfg = config();
  if (!cfg.token) {
    throw new Error("Read-only witness token is required for history.");
  }
  const query = new URLSearchParams({ relayOrigin: cfg.relayOrigin });
  const { data } = await requestJson(`/api/witness/admin/log?${query.toString()}`, { token: cfg.token });
  renderLatest(data.latest);
  renderHistory(data.history);
  log(`Witness history loaded for ${cfg.relayOrigin}.`);
}

async function loadSummary() {
  const cfg = config();
  if (!cfg.token) {
    throw new Error("Read-only witness token is required for summary.");
  }
  const { data } = await requestJson("/api/witness/admin/summary", { token: cfg.token });
  log(`Witness summary loaded. Max history ${data.maxHistory}; poll interval ${data.pollIntervalMs}ms.`);
}

async function run(action) {
  try {
    await action();
  } catch (error) {
    log(`Error: ${error.message}`);
    if (String(error.message).includes("token")) {
      badge(els.tokenBadge, "History: token needed", "warn");
    }
  }
}

function saveSession() {
  const cfg = config();
  sessionStorage.setItem(SESSION_KEYS.relayOrigin, cfg.relayOrigin);
  sessionStorage.setItem(SESSION_KEYS.witnessOrigin, cfg.witnessOrigin);
  if (cfg.token) {
    sessionStorage.setItem(SESSION_KEYS.token, cfg.token);
  }
  log("Saved witness console settings for this browser session.");
}

function clearSession() {
  sessionStorage.removeItem(SESSION_KEYS.token);
  els.tokenInput.value = "";
  badge(els.tokenBadge, "History: token required", "muted");
  log("Cleared session token.");
}

function hydrate() {
  els.witnessOriginInput.value = sessionStorage.getItem(SESSION_KEYS.witnessOrigin) || defaultWitnessOrigin();
  els.relayOriginInput.value = sessionStorage.getItem(SESSION_KEYS.relayOrigin) || DEFAULT_RELAY_ORIGIN;
  els.tokenInput.value = sessionStorage.getItem(SESSION_KEYS.token) || "";
}

function boot() {
  hydrate();
  els.refreshAll.addEventListener("click", () => run(async () => {
    await loadHealth();
    await loadPublicHead();
  }));
  els.loadPublicHead.addEventListener("click", () => run(loadPublicHead));
  els.loadHistory.addEventListener("click", () => run(loadHistory));
  els.loadSummary.addEventListener("click", () => run(loadSummary));
  els.saveSession.addEventListener("click", saveSession);
  els.clearSession.addEventListener("click", clearSession);
  run(async () => {
    await loadHealth();
    await loadPublicHead();
  });
}

boot();
