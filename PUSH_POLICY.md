# Notrus Push Policy

The current shipping production path in this repository is the native macOS client.

## Current rule

- Notrus Mac does not ship APNs, FCM, or provider-rendered push notifications.
- The packaged app does not declare push entitlements.
- The native source tree intentionally avoids remote-notification frameworks and local notification surfaces that would expose message timing or content on the lock screen by default.

## Why this is the current secure choice

- No message bodies are sent through third-party push infrastructure.
- No contact names are rendered by a notification provider outside the app.
- There is no lock-screen preview surface to misconfigure in the current shipping path.

## Future rule if push is added

- Push payloads must contain only a minimal wake-up token or queue hint.
- Message content must be fetched from the relay and decrypted inside the app.
- Contact names and previews must stay privacy-first and user-configurable.
- Any future push implementation must add dedicated notification-privacy tests before it can ship.
