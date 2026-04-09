import crypto from "node:crypto";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const appPath = path.join(root, "dist", "NotrusMac.app");
const zipPath = path.join(root, "dist", "NotrusMac.zip");
const binaryPath = path.join(appPath, "Contents", "MacOS", "NotrusMac");
const appIconPath = path.join(appPath, "Contents", "Resources", "AppIcon.icns");
const helperPaths = [
  path.join(appPath, "Contents", "Helpers", "notrus-protocol-core"),
  path.join(appPath, "Contents", "MacOS", "notrus-protocol-core"),
  path.join(appPath, "Contents", "Resources", "notrus-protocol-core"),
];
const infoPlistPath = path.join(appPath, "Contents", "Info.plist");
const appShaPath = path.join(root, "dist", "NotrusMac.app.sha256");
const zipShaPath = path.join(root, "dist", "NotrusMac.zip.sha256");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function sha256(filePath) {
  const data = await fs.readFile(filePath);
  return crypto.createHash("sha256").update(data).digest("hex");
}

async function parseShaSidecar(filePath) {
  const value = (await fs.readFile(filePath, "utf8")).trim();
  const match = value.match(/^([a-f0-9]{64})\s+/i);
  assert(match, `Invalid SHA-256 sidecar at ${filePath}.`);
  return match[1].toLowerCase();
}

async function codesignDetails(targetPath) {
  const { stderr } = await execFileAsync("codesign", ["-dv", "--verbose=4", targetPath]);
  return stderr;
}

async function codesignEntitlements(targetPath) {
  try {
    const { stdout } = await execFileAsync("codesign", ["-d", "--entitlements", ":-", targetPath]);
    return stdout;
  } catch (error) {
    return error.stdout ?? "";
  }
}

async function plistJson(filePath) {
  const { stdout } = await execFileAsync("plutil", ["-convert", "json", "-o", "-", filePath]);
  return JSON.parse(stdout);
}

async function helperSnapshot(helperPath) {
  return await new Promise((resolve, reject) => {
    const child = spawn(helperPath, [], {
      stdio: ["pipe", "pipe", "pipe"],
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
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `Helper exited with status ${code}.`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (error) {
        reject(error);
      }
    });

    child.stdin.end(JSON.stringify({ command: "profile-snapshot" }));
  });
}

function isLocalAtsExceptionMap(domains) {
  const allowedDomains = new Set(["127.0.0.1", "localhost"]);
  const keys = Object.keys(domains ?? {});
  return keys.every((key) => allowedDomains.has(key));
}

async function main() {
  const report = {
    appPath,
    helperPaths,
    checks: [],
  };

  const statTargets = [appPath, binaryPath, appIconPath, ...helperPaths, zipPath, infoPlistPath, appShaPath, zipShaPath];
  for (const target of statTargets) {
    await fs.stat(target);
  }

  const info = await plistJson(infoPlistPath);
  assert(info.CFBundleIdentifier === "com.notrus.mac", "Unexpected macOS bundle identifier.");
  assert(info.CFBundleExecutable === "NotrusMac", "Unexpected macOS bundle executable.");
  assert(info.CFBundleIconFile === "AppIcon", "Unexpected macOS bundle icon file.");
  assert(typeof info.NotrusLocalVerificationBuild === "boolean", "Missing Notrus local verification build flag.");
  assert(info.NSAppTransportSecurity?.NSAllowsArbitraryLoads === false, "ATS arbitrary loads must stay disabled.");
  assert(info.NSAppTransportSecurity?.NSAllowsLocalNetworking === true, "Local networking exception missing.");
  assert(isLocalAtsExceptionMap(info.NSAppTransportSecurity?.NSExceptionDomains), "ATS exceptions must stay limited to localhost.");
  report.checks.push("ats-policy");
  report.checks.push("app-icon");

  const appCodeSign = await codesignDetails(appPath);
  assert(appCodeSign.includes("Identifier=com.notrus.mac"), "App code-sign identity metadata missing.");
  assert(appCodeSign.includes("runtime"), "App must be signed with Hardened Runtime enabled.");
  report.checks.push("app-codesign");

  const releaseClass = appCodeSign.includes("Signature=adhoc") ? "local-verification-build" : "signed-release-candidate";
  report.releaseClass = releaseClass;
  if (releaseClass === "local-verification-build") {
    assert(info.NotrusLocalVerificationBuild === true, "Local verification builds must declare the local verification flag.");
  } else {
    assert(info.NotrusLocalVerificationBuild === false, "Signed release candidates must not declare local verification mode.");
  }

  const appEntitlements = await codesignEntitlements(appPath);
  if (releaseClass === "signed-release-candidate") {
    assert(appEntitlements.includes("com.apple.security.app-sandbox"), "App sandbox entitlement missing.");
    assert(appEntitlements.includes("com.apple.security.network.client"), "App network client entitlement missing.");
    assert(appEntitlements.includes("com.apple.security.files.user-selected.read-write"), "App file access entitlement missing.");
  } else {
    assert(!appEntitlements.includes("com.apple.security.app-sandbox"), "Local verification builds must not carry the sandbox entitlement.");
  }
  report.checks.push("app-entitlements");

  const snapshots = [];
  for (const helperPath of helperPaths) {
    snapshots.push({
      helperPath,
      snapshot: await helperSnapshot(helperPath),
    });
  }
  const snapshot = snapshots[0].snapshot;
  assert(snapshot.signal?.backend === "libsignal-protocol", "Signal standards backend missing from helper.");
  assert(snapshot.mls?.backend === "openmls", "MLS standards backend missing from helper.");
  for (const helper of snapshots.slice(1)) {
    assert(
      JSON.stringify(helper.snapshot) === JSON.stringify(snapshot),
      `Packaged helper snapshot mismatch for ${helper.helperPath}.`
    );
  }
  report.checks.push("helper-snapshot");

  const binarySha = await sha256(binaryPath);
  const expectedBinarySha = await parseShaSidecar(appShaPath);
  assert(binarySha === expectedBinarySha, "Mac binary checksum sidecar does not match packaged executable.");
  const zipSha = await sha256(zipPath);
  const expectedZipSha = await parseShaSidecar(zipShaPath);
  assert(zipSha === expectedZipSha, "Mac ZIP checksum sidecar does not match packaged archive.");
  report.checks.push("checksums");

  for (const helperPath of helperPaths) {
    const helperEntitlements = await codesignEntitlements(helperPath);
    assert(!helperEntitlements.includes("com.apple.security.app-sandbox"), `Helper should not be sandbox-entitled independently: ${helperPath}`);
  }
  report.checks.push("helper-entitlements");

  report.snapshot = snapshot;
  report.helperPathsVerified = helperPaths;
  report.binarySha256 = binarySha;
  report.zipSha256 = zipSha;

  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
