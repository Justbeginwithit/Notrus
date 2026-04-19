import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.join(__dirname, "..");

const ignoredDirectories = new Set([
  ".git",
  ".build",
  ".secrets",
  "dist",
  "node_modules",
  "target",
]);

const ignoredFiles = new Set([
  "data/store.json",
  "data/witness-store.json",
]);

const secretPatterns = [
  { label: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/u },
  { label: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/u },
  { label: "OpenAI key", pattern: /\bsk-[A-Za-z0-9]{20,}\b/u },
  { label: "Private key block", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----/u },
];

async function walk(directory, files = []) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolutePath = path.join(directory, entry.name);
    const relativePath = path.relative(root, absolutePath);
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) {
        await walk(absolutePath, files);
      }
      continue;
    }
    if (!ignoredFiles.has(relativePath)) {
      files.push(absolutePath);
    }
  }
  return files;
}

async function main() {
  const findings = [];
  const files = await walk(root);
  for (const file of files) {
    const fileStat = await stat(file);
    if (fileStat.size > 2_000_000) {
      continue;
    }

    const contents = await readFile(file, "utf8").catch(() => null);
    if (contents == null) {
      continue;
    }

    for (const { label, pattern } of secretPatterns) {
      if (pattern.test(contents)) {
        findings.push({
          file: path.relative(root, file),
          label,
        });
      }
    }
  }

  if (findings.length > 0) {
    for (const finding of findings) {
      console.error(`${finding.label}: ${finding.file}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log("secret-scan: no obvious committed secrets detected in the tracked source tree");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
