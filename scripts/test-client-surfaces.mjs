import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const rootDir = path.resolve(new URL("..", import.meta.url).pathname);
const sourceRoot = path.join(rootDir, "native", "macos", "NotrusMac", "Sources");
const packagedInfoPlist = path.join(rootDir, "dist", "Notrus.app", "Contents", "Info.plist");
const androidSourceRoot = path.join(rootDir, "native", "android", "NotrusAndroid", "app", "src", "main", "java");
const androidManifestPath = path.join(rootDir, "native", "android", "NotrusAndroid", "app", "src", "main", "AndroidManifest.xml");
const androidNetworkConfigPath = path.join(rootDir, "native", "android", "NotrusAndroid", "app", "src", "main", "res", "xml", "network_security_config.xml");
const androidBackupRulesPath = path.join(rootDir, "native", "android", "NotrusAndroid", "app", "src", "main", "res", "xml", "backup_rules.xml");
const androidExtractionRulesPath = path.join(rootDir, "native", "android", "NotrusAndroid", "app", "src", "main", "res", "xml", "data_extraction_rules.xml");

const forbiddenPatterns = [
  { pattern: /UserNotifications|UNUserNotificationCenter|aps-environment|FirebaseMessaging|FCM/i, reason: "push-notification surface" },
  { pattern: /NSPasteboard|UIPasteboard/i, reason: "clipboard surface" },
  { pattern: /onOpenURL|handlesExternalEvents|CFBundleURLTypes|LSItemContentTypes/i, reason: "deep-link or document-open surface" },
  { pattern: /NSSharingService|UIActivityViewController|ShareLink/i, reason: "share-sheet surface" },
  { pattern: /QuickLook|QLPreview|QLThumbnail/i, reason: "attachment preview surface" },
  { pattern: /dropDestination|onDrop|draggable|NSDragging|UIDropInteraction/i, reason: "drag-and-drop surface" },
  { pattern: /\bAmplitude\b|\bMixpanel\b|\bSegment\b|\bTelemetryDeck\b|\bFirebaseAnalytics\b|\bPostHog\b/i, reason: "analytics SDK" },
];

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(absolute)));
    } else if (entry.isFile()) {
      files.push(absolute);
    }
  }
  return files;
}

async function main() {
  const files = (await listFiles(sourceRoot)).filter((file) => file.endsWith(".swift"));
  const violations = [];

  for (const file of files) {
    const contents = await readFile(file, "utf8");
    for (const rule of forbiddenPatterns) {
      if (rule.pattern.test(contents)) {
        violations.push(`${path.relative(rootDir, file)} matched forbidden ${rule.reason}`);
      }
    }
  }

  const infoPlist = await readFile(packagedInfoPlist, "utf8").catch(() => "");
  if (infoPlist.includes("CFBundleURLTypes") || infoPlist.includes("LSItemContentTypes") || infoPlist.includes("aps-environment")) {
    violations.push("dist/Notrus.app/Contents/Info.plist exposes URL, document, or push entitlements.");
  }

  const androidFiles = (await listFiles(androidSourceRoot).catch(() => [])).filter((file) => file.endsWith(".kt"));
  for (const file of androidFiles) {
    const contents = await readFile(file, "utf8");
    for (const rule of forbiddenPatterns) {
      if (rule.pattern.test(contents)) {
        violations.push(`${path.relative(rootDir, file)} matched forbidden ${rule.reason}`);
      }
    }
  }

  const androidManifest = await readFile(androidManifestPath, "utf8").catch(() => "");
  if (!androidManifest.includes('android:allowBackup="false"')) {
    violations.push("AndroidManifest.xml does not disable generic app backup.");
  }
  if (!androidManifest.includes('android:usesCleartextTraffic="false"')) {
    violations.push("AndroidManifest.xml allows cleartext traffic.");
  }
  if (/android:exported="true"/.test(androidManifest) && !androidManifest.includes("android.intent.category.LAUNCHER")) {
    violations.push("AndroidManifest.xml exports non-launcher surfaces.");
  }

  const networkConfig = await readFile(androidNetworkConfigPath, "utf8").catch(() => "");
  if (!networkConfig.includes('cleartextTrafficPermitted="false"')) {
    violations.push("Android network security config is missing the cleartext deny base rule.");
  }

  const backupRules = await readFile(androidBackupRulesPath, "utf8").catch(() => "");
  if (!backupRules.includes("notrus_vault.xml")) {
    violations.push("Android backup rules are missing the encrypted vault exclusion.");
  }

  const extractionRules = await readFile(androidExtractionRulesPath, "utf8").catch(() => "");
  if (!extractionRules.includes("notrus_vault.xml")) {
    violations.push("Android data extraction rules are missing the encrypted vault exclusion.");
  }

  if (violations.length > 0) {
    throw new Error(violations.join("\n"));
  }

  console.log("client-surfaces: macOS and Android client bundles expose no forbidden push, analytics, clipboard, deep-link, share-sheet, drag-drop, preview, cleartext, or backup-leak surfaces");
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
