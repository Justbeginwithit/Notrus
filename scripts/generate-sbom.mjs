import { readFile, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.join(__dirname, "..");
const outputDir = path.join(root, "dist", "sbom");
const outputPath = path.join(outputDir, "notrus-sbom.json");

function parseCargoLock(lockfile) {
  const packages = [];
  const blocks = lockfile.split("\n[[package]]\n").slice(1);
  for (const block of blocks) {
    const name = block.match(/^name = "([^"]+)"/m)?.[1];
    const version = block.match(/^version = "([^"]+)"/m)?.[1];
    if (!name || !version) {
      continue;
    }
    packages.push({
      ecosystem: "cargo",
      name,
      version,
    });
  }
  return packages;
}

function parseSwiftDependencies(packageSwift) {
  return [...packageSwift.matchAll(/\.package\([^)]*url:\s*"([^"]+)"[^)]*from:\s*"([^"]+)"/g)].map((match) => ({
    ecosystem: "swiftpm",
    name: match[1].split("/").pop()?.replace(/\.git$/u, "") ?? match[1],
    source: match[1],
    versionConstraint: `from ${match[2]}`,
  }));
}

async function main() {
  const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  const cargoLock = await readFile(path.join(root, "native", "protocol-core", "Cargo.lock"), "utf8");
  const swiftPackage = await readFile(path.join(root, "native", "macos", "NotrusMac", "Package.swift"), "utf8");

  const sbom = {
    generatedAt: new Date().toISOString(),
    name: "Notrus",
    version: packageJson.version,
    components: [
      ...Object.entries(packageJson.dependencies ?? {}).map(([name, version]) => ({
        ecosystem: "npm",
        name,
        version,
      })),
      ...Object.entries(packageJson.devDependencies ?? {}).map(([name, version]) => ({
        ecosystem: "npm-dev",
        name,
        version,
      })),
      ...parseCargoLock(cargoLock),
      ...parseSwiftDependencies(swiftPackage),
    ],
  };

  await mkdir(outputDir, { recursive: true });
  await rm(path.join(outputDir, "aegis-sbom.json"), { force: true });
  await writeFile(outputPath, JSON.stringify(sbom, null, 2));
  console.log(`Generated SBOM at ${outputPath}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
