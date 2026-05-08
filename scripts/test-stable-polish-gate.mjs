#!/usr/bin/env node

import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath) {
  return readFileSync(path.join(rootDir, relativePath), "utf8");
}

function assert(condition, message) {
  if (!condition) {
    console.error(`stable-polish-gate: ${message}`);
    process.exit(1);
  }
}

const requiredDocs = [
  "docs/STABLE_POLISH_GATE.md",
  "STABLE_RELEASE_CHECKLIST.md",
];

for (const relativePath of requiredDocs) {
  assert(existsSync(path.join(rootDir, relativePath)), `missing required polish doc ${relativePath}`);
}

const androidUi = read("native/android/NotrusAndroid/app/src/main/java/com/notrus/android/ui/NotrusAndroidApp.kt");
const androidViewModel = read("native/android/NotrusAndroid/app/src/main/java/com/notrus/android/ui/NotrusViewModel.kt");
const androidModels = read("native/android/NotrusAndroid/app/src/main/java/com/notrus/android/model/Models.kt");
const macApp = read("native/macos/NotrusMac/Sources/NotrusMacApp.swift");
const macModel = read("native/macos/NotrusMac/Sources/AppModel.swift");
const packageJson = read("package.json");
const stableChecklist = read("STABLE_RELEASE_CHECKLIST.md");

assert(
  androidUi.includes("key = { message -> message.id }") &&
    androidUi.includes("contentType = { message -> message.status }"),
  "Android message LazyColumn must keep stable keys and content types for row reuse"
);

assert(
  androidUi.includes("MessageAutoScrollDelayMs") &&
    androidUi.includes("messageListState.scrollToItem(thread.messages.lastIndex)"),
  "Android conversation must settle layout before jumping to the latest message"
);

assert(
  androidUi.includes("remember(text, trimmedQuery, highlightBackground, highlightForeground)"),
  "Android search highlighting must be memoized instead of rebuilt on every recomposition"
);

assert(
  !androidUi.includes(".background(bubbleColor)\n                .animateContentSize"),
  "Android message bubbles must not animate full content-size changes in the hot message list"
);

assert(
  androidViewModel.includes("withContext(Dispatchers.Default)") &&
    androidViewModel.includes("materializeThreads("),
  "Android sync materialization must run off the UI thread"
);

assert(
  androidUi.includes("HapticFeedbackConstants") &&
    androidUi.includes("performNotrusHaptic") &&
    androidModels.includes("hapticFeedbackEnabled: Boolean = true") &&
    androidViewModel.includes("KEY_HAPTIC_FEEDBACK_ENABLED") &&
    androidViewModel.includes("fun updateHapticFeedback"),
  "Android must expose subtle configurable haptic feedback for stable-release polish"
);

const powFieldMatches = androidModels.match(/val powDifficultyBits: Int\? = null/g) ?? [];
assert(powFieldMatches.length === 1, "Android RelayAbuseControls must not duplicate powDifficultyBits");

assert(
  macApp.includes("@Environment(\\.accessibilityReduceMotion)") &&
    macApp.includes("let shouldAnimate = animated && !reduceMotion"),
  "macOS chat/search motion must respect Reduce Motion"
);

assert(
  macApp.includes("LazyVStack(alignment: .leading, spacing: 12)"),
  "macOS message history must use LazyVStack for long conversations"
);

assert(
  macApp.includes("let matchSet = Set(matches)") &&
    macApp.includes("searchMatchVisible: matchSet.contains(message.id)"),
  "macOS message search must compute match membership once per render"
);

assert(
  macApp.includes("Task.sleep(nanoseconds: 80_000_000)") &&
    macApp.includes("proxy.scrollTo(bottomAnchorId, anchor: .bottom)"),
  "macOS sync/live updates must settle layout and then scroll to the newest message"
);

assert(
  macModel.includes("private func publishIfChanged<Value: Equatable>") &&
    macModel.includes("publishIfChanged(\\.threads, visibleThreads)") &&
    macModel.includes("publishIfChanged(\\.archivedThreads, archived)"),
  "macOS sync must avoid republishing unchanged thread lists"
);

assert(
  macApp.includes("NSHapticFeedbackManager") &&
    macApp.includes("NotrusHapticFeedback.perform") &&
    macModel.includes("@Published var hapticFeedbackEnabled") &&
    macModel.includes("persistHapticFeedbackPreference"),
  "macOS must expose no-op-safe configurable haptic feedback where hardware supports it"
);

assert(
  packageJson.includes("\"test:stable-polish-gate\""),
  "package.json must expose npm run test:stable-polish-gate"
);

assert(
  stableChecklist.includes("Stable polish gate") &&
    stableChecklist.includes("npm run test:stable-polish-gate"),
  "stable release checklist must include the stable polish gate"
);

console.log("stable-polish-gate: Android/macOS polish invariants passed");
