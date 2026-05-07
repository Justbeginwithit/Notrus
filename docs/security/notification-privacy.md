# Notification Privacy

Android and macOS notifications are privacy-safe by default.

## Default

Notification content is hidden by default. The generic notification text should not include message bodies.

## Optional preview modes

- Hidden: app name or generic new-message text only.
- Sender only: sender name without body text.
- Full preview: sender name and locally decrypted preview text.

Full preview must be an explicit user choice. Message previews are decrypted on the device after local sync; plaintext is not sent in a relay wake-up payload.

macOS notifications are local `UserNotifications` generated after the Mac client syncs and decrypts a new message. The Mac app now keeps running after the last window is closed so live sync and local notifications can continue while Notrus remains open in the Dock/menu bar. They do not use APNs or third-party push services in this build, so notifications are not expected after the app is fully quit with Quit/Command-Q.

Foreground behavior:

- Android suppresses background notifications while the app process is foreground/visible.
- macOS suppresses new-message notification banners while the app is active.
- Muted chats do not notify.
- Archived chats still notify unless muted. Archive is a local organization state, not a privacy mute.
- Notification requests are deduplicated by thread/message identity where the platform allows it.

## Privacy mode

Privacy mode should keep notification content hidden unless the user explicitly overrides that behavior.

## Reliability boundary

WorkManager, foreground background delivery, OEM battery policy, notification permissions, force-stop behavior, macOS notification authorization, app sleep, and network loss can delay or prevent notifications. Notrus notifications should not be marketed as emergency-grade delivery.
