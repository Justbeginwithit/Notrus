import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = fileURLToPath(new URL("..", import.meta.url));
const relayPort = Number(process.env.NOTRUS_SECURITY_SUITE_PORT || 3070);
const relayOrigin = process.env.NOTRUS_SECURITY_SUITE_RELAY_ORIGIN ?? `http://127.0.0.1:${relayPort}`;
const managedRelay = !process.env.NOTRUS_SECURITY_SUITE_RELAY_ORIGIN;

function runCommand(command, args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: rootDir,
      env: {
        ...process.env,
        ...extraEnv,
      },
      stdio: "inherit",
    });

    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} ${args.join(" ")} failed with exit code ${code ?? "unknown"}.`));
    });
  });
}

async function requestJson(origin, pathname) {
  const url = new URL(pathname, origin);
  let transport = http;
  if (url.protocol === "https:") {
    const https = await import("node:https");
    transport = https.default;
  }
  return new Promise((resolve, reject) => {
    const request = transport.request(
      url,
      {
        method: "GET",
        headers: { Accept: "application/json" },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let decoded = {};
          try {
            decoded = raw ? JSON.parse(raw) : {};
          } catch {
            decoded = { raw };
          }
          resolve({
            body: decoded,
            statusCode: response.statusCode ?? 0,
          });
        });
      }
    );
    request.on("error", reject);
    request.end();
  });
}

async function waitForHealth(origin) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const response = await requestJson(origin, "/api/health");
      if (response.statusCode === 200) {
        return;
      }
    } catch {
      // keep waiting
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for relay health at ${origin}.`);
}

async function startRelay() {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "notrus-security-suite-"));
  const storePath = path.join(tempRoot, "store.json");
  const relay = spawn(process.execPath, ["server.js"], {
    cwd: rootDir,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      NOTRUS_DATA_DIR: tempRoot,
      NOTRUS_PROTOCOL_POLICY: "require-standards",
      PORT: String(relayPort),
    },
    stdio: "ignore",
  });

  await waitForHealth(relayOrigin);

  return {
    relay,
    storePath,
    tempRoot,
  };
}

async function stopRelay(state) {
  if (!state) {
    return;
  }
  const { relay, tempRoot } = state;

  if (relay && !relay.killed) {
    relay.kill("SIGTERM");
    await new Promise((resolve) => relay.once("exit", resolve));
  }

  if (tempRoot) {
    await rm(tempRoot, { force: true, recursive: true });
  }
}

async function main() {
  let relayState = null;
  if (managedRelay) {
    relayState = await startRelay();
  }

  const routingEnv = {
    NOTRUS_ADVERSARIAL_RELAY_ORIGIN: relayOrigin,
    NOTRUS_CONTENT_RELAY_ORIGIN: relayOrigin,
    NOTRUS_METADATA_RELAY_ORIGIN: relayOrigin,
    ...(relayState?.storePath ? { NOTRUS_METADATA_STORE_PATH: relayState.storePath } : {}),
    NOTRUS_PRIVACY_RELAY_ORIGIN: relayOrigin,
  };

  try {
    await runCommand("npm", ["run", "scan:secrets"]);
    await runCommand("npm", ["run", "test:attestation-service"]);
    await runCommand("npm", ["run", "test:attestation-enforcement"]);
    await runCommand("npm", ["run", "test:client-surfaces"]);
    await runCommand("npm", ["run", "test:metadata-boundary"], routingEnv);
    await runCommand("npm", ["run", "test:content-boundary"], routingEnv);
    await runCommand("npm", ["run", "test:production-api-boundary"]);
    await runCommand("npm", ["run", "test:privacy-routing"], routingEnv);
    await runCommand("npm", ["run", "test:standards-e2e"]);
    await runCommand("npm", ["run", "test:mls-fanout-compat"]);
    await runCommand("npm", ["run", "test:recovery-lifecycle"]);
    await runCommand("npm", ["run", "test:retention-pruning"]);
    await runCommand("npm", ["run", "test:adversarial-inputs"], routingEnv);
    await runCommand("npm", ["run", "test:abuse-controls"]);
    await runCommand("npm", ["run", "test:device-membership"]);
  } finally {
    if (managedRelay) {
      await stopRelay(relayState);
    }
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
