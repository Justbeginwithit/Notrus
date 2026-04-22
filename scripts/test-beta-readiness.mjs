import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const rootDir = fileURLToPath(new URL("..", import.meta.url));
const androidProjectDir = path.join(rootDir, "native/android/NotrusAndroid");
const androidMode = (process.env.NOTRUS_BETA_ANDROID_MODE ?? "auto").toLowerCase();
const defaultRelayOrigin = process.env.NOTRUS_BETA_RELAY_ORIGIN ?? "http://127.0.0.1:3000";

function runCommand(command, args, options = {}) {
  const { cwd = rootDir, env = {} } = options;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: {
        ...process.env,
        ...env,
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

function capture(command, args, options = {}) {
  const { cwd = rootDir, env = {} } = options;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: {
        ...process.env,
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });

    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      reject(
        new Error(
          `${command} ${args.join(" ")} failed with exit code ${code ?? "unknown"}.\n${stderr || stdout}`.trim()
        )
      );
    });
  });
}

async function hasConnectedAndroidDevice() {
  const { stdout } = await capture("adb", ["devices"]);
  const lines = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !line.startsWith("List of devices attached"));
  return lines.some((line) => line.endsWith("\tdevice"));
}

async function relayHealthy(origin) {
  try {
    const response = await fetch(new URL("/api/health", origin), {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function maybeRunAndroidSuites() {
  if (androidMode === "skip") {
    console.log("beta-readiness: Android connected suites skipped (NOTRUS_BETA_ANDROID_MODE=skip).");
    return;
  }

  const connected = await hasConnectedAndroidDevice();
  if (!connected) {
    if (androidMode === "required") {
      throw new Error("beta-readiness: no connected Android device or emulator found (required mode).");
    }
    console.log("beta-readiness: no connected Android device/emulator found; skipping Android connected suites.");
    return;
  }

  await runCommand("./gradlew", [
    "connectedDebugAndroidTest",
    "-Pandroid.testInstrumentationRunnerArguments.class=com.notrus.android.relay.RelayClientInstrumentedTest",
  ], { cwd: androidProjectDir });

  await runCommand("./gradlew", [
    "connectedDebugAndroidTest",
    "-Pandroid.testInstrumentationRunnerArguments.class=com.notrus.android.security.AndroidLocalSecurityInstrumentedTest",
  ], { cwd: androidProjectDir });
}

async function main() {
  const securitySuiteEnv = {};
  if (await relayHealthy(defaultRelayOrigin)) {
    securitySuiteEnv.NOTRUS_SECURITY_SUITE_RELAY_ORIGIN = defaultRelayOrigin;
  }

  await runCommand("npm", ["run", "test:security-suite"], {
    env: securitySuiteEnv,
  });
  await runCommand("npm", ["run", "test:mac-app"]);
  await maybeRunAndroidSuites();
  console.log("beta-readiness: relay, macOS, and available Android beta gates passed.");
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
