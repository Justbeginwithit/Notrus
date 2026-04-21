import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export async function withManagedRelay({
  compatibilityRoutes = false,
  envOriginName,
  port,
  protocolPolicy = "require-standards",
}, callback) {
  const externalOrigin = process.env[envOriginName];
  if (externalOrigin) {
    await callback({
      managed: false,
      origin: externalOrigin,
      storePath: process.env[envOriginName.replace(/_ORIGIN$/, "_STORE_PATH")] ?? null,
    });
    return;
  }

  const tempDir = await mkdtemp(path.join(os.tmpdir(), "notrus-managed-relay-"));
  const origin = `http://127.0.0.1:${port}`;
  const storePath = path.join(tempDir, "data", "store.json");
  const relay = spawn(process.execPath, ["server.js"], {
    cwd: path.resolve(new URL("..", import.meta.url).pathname),
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      NOTRUS_DATA_DIR: path.join(tempDir, "data"),
      NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES: compatibilityRoutes ? "true" : "false",
      NOTRUS_PROTOCOL_POLICY: protocolPolicy,
      NOTRUS_SECRET_DIR: path.join(tempDir, "secrets"),
      PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let output = "";
  relay.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  relay.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });

  try {
    await waitForRelay(relay, origin, () => output);
    await callback({ managed: true, origin, storePath });
  } finally {
    relay.kill("SIGTERM");
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function waitForRelay(child, origin, output) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Relay exited early with status ${child.exitCode}.\n${output()}`);
    }
    try {
      const response = await fetch(`${origin}/api/health`);
      if (response.ok) {
        return;
      }
    } catch {
      // Keep polling until the managed relay is ready.
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`Timed out waiting for managed relay at ${origin}.\n${output()}`);
}
