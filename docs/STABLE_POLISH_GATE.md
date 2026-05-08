# Stable Polish Gate

This gate tracks the non-cryptographic quality work required before Notrus is called stable. Security still matters first, but a stable secure messenger must also feel smooth, predictable, native, and visually consistent.

## Required Product Bar

Stable UI must be:

- smooth in chat list and message list scrolling
- responsive while syncing, decrypting, sending, importing, exporting, and handling attachments
- visually consistent across Android and macOS
- predictable for archive, delete, search, notification, receipt, and sync state
- subtle and non-noisy in its haptic confirmations, with a visible off switch
- free of prototype/debug-looking primary surfaces
- respectful of Android remove-animations and macOS reduce-motion preferences

## Android Implementation Rules

- Keep message and conversation lists lazy with stable item keys.
- Use content types for high-volume lazy message rows so Compose can reuse item composition more predictably.
- Keep sync materialization, crypto, JSON processing, and attachment preparation off the UI thread.
- Do not show full-screen sync/loading indicators for silent automatic sync.
- Avoid `animateContentSize` on high-frequency message bubbles because receipt/edit/search changes can otherwise create keyboard and list jitter.
- Keep message search in top chrome, not as a large inline panel inside the conversation body.
- Keep notification, archive, delete, search, and receipt behavior consistent with macOS wording.
- Use subtle in-app haptics for send, long-press/message actions, archive, delete, mute, read/privacy setting changes, account export/import success, failed sends, and security-sensitive warnings.
- Respect the app-level Haptic feedback setting and Android system haptic/vibration controls; do not vibrate for every sync update or incoming message outside normal notification settings.

## macOS Implementation Rules

- Use lazy message rendering for long histories.
- Avoid rebuilding published lists when a sync result is unchanged.
- Auto-scroll to the latest message after layout settles so manual sync/live sync does not leave the newest message just below the viewport.
- Respect `accessibilityReduceMotion` for chat/search scrolling.
- Keep the conversation surface as a clean native Mac layout, with heavy glass/box effects reserved for small cards rather than large scrolling regions.
- Prefer native context menus, search fields, sidebars, and keyboard-friendly flows.
- Use `NSHapticFeedbackManager` only as optional, hardware-dependent confirmation for sends, message actions, archive/delete/mute, export/import success, and important warnings.
- If a Mac has no compatible haptic device, the haptic path must safely do nothing and the UI must still show visible state.

## Manual Profiling Before Stable

Run these on release or profileable builds, not only debug builds:

- Android startup, chat list scroll, message list scroll, open chat, send message, live receive, attachment row, notification-triggered sync.
- macOS launch, sidebar scroll, message list scroll, open thread, live sync update, send/receive, attachment row.
- At least one realistic history with 1000+ messages and several attachment records.
- Slow relay/network test with reconnect and live event fallback.

## Current Automated Gate

Run:

```sh
npm run test:stable-polish-gate
```

This is a static quality gate. It does not replace Android Studio Profiler, Perfetto, Instruments, or real-device testing, but it prevents obvious regressions in the current polish work.
