const storage = {
  origin: "notrus_admin_origin",
  token: "notrus_admin_token",
  limit: "notrus_admin_limit",
  includeDeactivated: "notrus_admin_include_deactivated",
};

const els = {
  originInput: document.getElementById("originInput"),
  tokenInput: document.getElementById("tokenInput"),
  limitInput: document.getElementById("limitInput"),
  searchInput: document.getElementById("searchInput"),
  includeDeactivatedInput: document.getElementById("includeDeactivatedInput"),
  refreshHealth: document.getElementById("refreshHealth"),
  saveConfig: document.getElementById("saveConfig"),
  loadUsers: document.getElementById("loadUsers"),
  listAllUsers: document.getElementById("listAllUsers"),
  queryUsers: document.getElementById("queryUsers"),
  healthBadge: document.getElementById("healthBadge"),
  adminBadge: document.getElementById("adminBadge"),
  statsText: document.getElementById("statsText"),
  userCountText: document.getElementById("userCountText"),
  usersBody: document.getElementById("usersBody"),
  logBox: document.getElementById("logBox"),
};

function nowIso() {
  return new Date().toISOString();
}

function log(line) {
  const prefix = `[${nowIso()}] `;
  els.logBox.textContent = `${prefix}${line}\n${els.logBox.textContent}`.slice(0, 10000);
}

function normalizeOrigin(value) {
  const fallback = window.location.origin;
  const trimmed = (value || "").trim();
  if (!trimmed) {
    return fallback;
  }
  try {
    const parsed = new URL(trimmed);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return fallback;
  }
}

function getConfig() {
  return {
    origin: normalizeOrigin(els.originInput.value),
    token: els.tokenInput.value.trim(),
    limit: Math.max(1, Math.min(1000, Number(els.limitInput.value || "200") || 200)),
    query: els.searchInput.value.trim(),
    includeDeactivated: Boolean(els.includeDeactivatedInput.checked),
  };
}

function saveConfig() {
  const cfg = getConfig();
  localStorage.setItem(storage.origin, cfg.origin);
  localStorage.setItem(storage.token, cfg.token);
  localStorage.setItem(storage.limit, String(cfg.limit));
  localStorage.setItem(storage.includeDeactivated, cfg.includeDeactivated ? "true" : "false");
  log("Saved local admin UI config.");
}

function hydrateConfig() {
  const fallbackOrigin = window.location.origin;
  els.originInput.value = localStorage.getItem(storage.origin) || fallbackOrigin;
  els.tokenInput.value = localStorage.getItem(storage.token) || "";
  els.limitInput.value = localStorage.getItem(storage.limit) || "200";
  els.includeDeactivatedInput.checked = localStorage.getItem(storage.includeDeactivated) === "true";
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data.error || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return data;
}

async function loadHealth() {
  const { origin } = getConfig();
  try {
    const health = await requestJson(`${origin}/api/health`);
    const ok = health.ok === true;
    const adminEnabled = Boolean(health.adminApi && health.adminApi.enabled);
    els.healthBadge.textContent = `Health: ${ok ? "ok" : "not ok"}`;
    els.healthBadge.className = `badge ${ok ? "ok" : "warn"}`;
    els.adminBadge.textContent = `Admin API: ${adminEnabled ? "enabled" : "disabled"}`;
    els.adminBadge.className = `badge ${adminEnabled ? "ok" : "warn"}`;
    log(`Health loaded from ${origin}. Admin API ${adminEnabled ? "enabled" : "disabled"}.`);
    return health;
  } catch (error) {
    els.healthBadge.textContent = "Health: error";
    els.healthBadge.className = "badge warn";
    els.adminBadge.textContent = "Admin API: unknown";
    els.adminBadge.className = "badge muted";
    log(`Health request failed: ${error.message}`);
    throw error;
  }
}

function userStatusLabel(user) {
  if (user.deactivatedAt) {
    return "deactivated";
  }
  return "active";
}

function renderUsers(users) {
  if (!Array.isArray(users) || users.length === 0) {
    els.usersBody.innerHTML = '<tr><td colspan="7" class="muted">No users matched this query.</td></tr>';
    return;
  }
  els.usersBody.innerHTML = "";
  for (const user of users) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(user.username || "")}</td>
      <td>${escapeHtml(user.displayName || "")}</td>
      <td class="mono">${escapeHtml(user.id || "")}</td>
      <td>${Number(user.activeDeviceCount || 0)} active / ${Number(user.revokedDeviceCount || 0)} revoked</td>
      <td>${Number(user.threadCount || 0)}</td>
      <td>${escapeHtml(userStatusLabel(user))}</td>
      <td class="actions"></td>
    `;

    const actions = tr.querySelector(".actions");
    if (user.deactivatedAt) {
      const unblockBtn = document.createElement("button");
      unblockBtn.type = "button";
      unblockBtn.className = "button";
      unblockBtn.textContent = "Unblock";
      unblockBtn.addEventListener("click", async () => {
        await unblockUser(user);
      });
      actions.appendChild(unblockBtn);
    } else {
      const blockBtn = document.createElement("button");
      blockBtn.type = "button";
      blockBtn.className = "button subtle";
      blockBtn.textContent = "Block";
      blockBtn.addEventListener("click", async () => {
        await blockUser(user.id, user.username);
      });
      actions.appendChild(blockBtn);
    }

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "button danger";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", async () => {
      await deleteUser(user.id, user.username);
    });

    actions.appendChild(deleteBtn);
    els.usersBody.appendChild(tr);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function loadUsers({ all = false } = {}) {
  const cfg = getConfig();
  saveConfig();
  const params = new URLSearchParams();
  if (all) {
    params.set("all", "true");
    params.set("limit", "all");
    params.set("includeDeactivated", "true");
  } else {
    params.set("limit", String(cfg.limit));
  }
  if (!all && cfg.query) {
    params.set("q", cfg.query);
  }
  if (cfg.includeDeactivated) {
    params.set("includeDeactivated", "true");
  }

  if (!cfg.token) {
    log("Admin token is missing.");
    throw new Error("Admin token is required.");
  }

  const data = await requestJson(`${cfg.origin}/api/admin/users?${params.toString()}`, {
    headers: {
      "X-Notrus-Admin-Token": cfg.token,
    },
  });

  renderUsers(data.users || []);
  els.userCountText.textContent = `${Number(data.users?.length || 0)} shown`;
  const totalMatched = Number(data.totalMatched ?? data.users?.length ?? 0);
  const truncated = Boolean(data.truncated);
  els.statsText.textContent = `Relay users: ${Number(data.relayUsers || 0)} · Relay threads: ${Number(data.relayThreads || 0)} · Matched: ${totalMatched}${truncated ? " (truncated)" : ""}`;
  log(`Loaded ${Number(data.users?.length || 0)} users${all ? " (all mode)" : ""}.`);
}

async function blockUser(userId, username) {
  const cfg = getConfig();
  if (!confirm(`Block user @${username} (${userId})? This deactivates and tombstones the account.`)) {
    return;
  }
  await requestJson(`${cfg.origin}/api/admin/users/${encodeURIComponent(userId)}/block`, {
    method: "POST",
    headers: {
      "X-Notrus-Admin-Token": cfg.token,
    },
  });
  log(`Blocked user @${username} (${userId}).`);
  await loadUsers();
}

async function deleteUser(userId, username) {
  const cfg = getConfig();
  if (!confirm(`Delete user @${username} (${userId}) permanently?\nThis removes relay account and related threads.`)) {
    return;
  }
  await requestJson(`${cfg.origin}/api/admin/users/${encodeURIComponent(userId)}/delete`, {
    method: "POST",
    headers: {
      "X-Notrus-Admin-Token": cfg.token,
    },
  });
  log(`Deleted user @${username} (${userId}).`);
  await loadUsers();
}

async function unblockUser(user) {
  const cfg = getConfig();
  const suggested = (user.previousUsernameHint || "").trim();
  const restoredUsername = prompt(
    `Restore username for user ID ${user.id}:`,
    suggested || "",
  );
  if (!restoredUsername) {
    return;
  }
  await requestJson(`${cfg.origin}/api/admin/users/${encodeURIComponent(user.id)}/unblock`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Notrus-Admin-Token": cfg.token,
    },
    body: JSON.stringify({
      username: restoredUsername.trim(),
      restoreDevices: true,
    }),
  });
  log(`Unblocked user ${user.id} with username @${restoredUsername.trim()}.`);
  await loadUsers();
}

async function boot() {
  hydrateConfig();
  els.saveConfig.addEventListener("click", () => {
    saveConfig();
  });
  els.refreshHealth.addEventListener("click", async () => {
    try {
      await loadHealth();
    } catch {}
  });
  els.loadUsers.addEventListener("click", async () => {
    try {
      await loadUsers();
    } catch (error) {
      log(`Load users failed: ${error.message}`);
      alert(error.message);
    }
  });
  els.listAllUsers.addEventListener("click", async () => {
    try {
      await loadUsers({ all: true });
    } catch (error) {
      log(`List all users failed: ${error.message}`);
      alert(error.message);
    }
  });
  els.queryUsers.addEventListener("click", async () => {
    try {
      await loadUsers();
    } catch (error) {
      log(`Query failed: ${error.message}`);
      alert(error.message);
    }
  });

  try {
    await loadHealth();
    if (els.tokenInput.value.trim()) {
      await loadUsers({ all: true });
    }
  } catch {}
}

boot();
