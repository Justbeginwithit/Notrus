import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = fileURLToPath(new URL("..", import.meta.url));

const requiredSecurityDocs = [
  "docs/security/emergency-readiness.md",
  "docs/security/endpoint-provider-guide.md",
  "docs/security/metadata-exposure.md",
  "docs/security/relay-operator-powers.md",
  "docs/security/admin-api.md",
  "docs/security/recovery-backup.md",
  "docs/security/group-behavior.md",
  "docs/security/notification-privacy.md",
  "docs/security/android-local-security.md",
  "docs/security/macos-local-security.md",
  "docs/security/self-hosting-security.md",
  "docs/security/known-limitations.md",
  "docs/security/audit-status.md",
  "docs/security/release-verification.md",
  "SECURITY_SCANNER_STATUS.md",
];

const publicDocs = [
  "README.md",
  "SECURITY.md",
  "RELEASE_NOTES.md",
  "SECURITY_SCANNER_STATUS.md",
  "fdroid/metadata/com.notrus.android.yml",
  "fastlane/metadata/android/en-US/full_description.txt",
  "fastlane/metadata/android/en-US/short_description.txt",
  ...requiredSecurityDocs,
];

const bannedPublicClaims = [
  /\bfully secure\b/i,
  /\bunbreakable\b/i,
  /\bmilitary-grade security\b/i,
  /\bsafe for emergencies\b/i,
  /\bsafe for activists\b/i,
  /\bsafe for journalists\b/i,
  /\bsafe for lawyers\b/i,
  /\bmetadata-free\b/i,
  /\banonymous messenger\b/i,
  /\bpost-quantum secure messenger\b/i,
  /\brelay sees nothing\b/i,
  /\b(has been|is|was) independently audited\b/i,
  /\bproduction hardened\b/i,
];

const requiredPublicPhrases = [
  "designed for private end-to-end encrypted messaging",
  "post-quantum hybrid direct-message session setup",
  "relay still sees some metadata",
  "not independently audited",
  "not recommended as the only emergency channel",
];

const requiredScannerSections = [
  "## Semgrep",
  "## SonarCloud",
  "## CodeQL",
  "## Dependency scanning",
  "## Secret scanning",
  "## False positives",
];

async function fileText(relativePath) {
  return readFile(path.join(rootDir, relativePath), "utf8");
}

async function assertExists(relativePath) {
  await access(path.join(rootDir, relativePath));
}

async function runCommand(command, args, extraEnv = {}) {
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

async function checkDocsExist() {
  for (const doc of requiredSecurityDocs) {
    await assertExists(doc);
  }
}

async function checkPublicWording() {
  const combined = [];
  for (const doc of publicDocs) {
    combined.push(`\n--- ${doc} ---\n${await fileText(doc)}`);
  }
  const text = combined.join("\n");

  for (const claim of bannedPublicClaims) {
    assert.equal(claim.test(text), false, `Public docs contain banned or over-strong claim matching ${claim}.`);
  }

  for (const phrase of requiredPublicPhrases) {
    assert.equal(text.toLowerCase().includes(phrase.toLowerCase()), true, `Public docs must include: ${phrase}`);
  }
}

async function checkScannerStatus() {
  const status = await fileText("SECURITY_SCANNER_STATUS.md");
  for (const section of requiredScannerSections) {
    assert.equal(status.includes(section), true, `SECURITY_SCANNER_STATUS.md is missing ${section}.`);
  }
  assert.match(status, /no unresolved high or critical findings/i);
  assert.match(status, /false positive/i);
  assert.match(status, /127\.0\.0\.1/);
  assert.match(status, /::ffff:127\.0\.0\.1/);
}

async function main() {
  await checkDocsExist();
  await checkPublicWording();
  await checkScannerStatus();

  if (process.env.NOTRUS_EMERGENCY_GATE_SKIP_SECURITY_SUITE !== "true") {
    await runCommand("npm", ["run", "test:security-suite"], {
      NOTRUS_SECURITY_SUITE_PORT: process.env.NOTRUS_EMERGENCY_GATE_SECURITY_PORT ?? "3080",
    });
  }

  console.log("emergency-trust-gate: docs, wording, scanner evidence, and security suite checks passed");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
