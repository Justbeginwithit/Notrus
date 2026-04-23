# Notrus Push Policy

## Current rule

- Notrus does not ship APNs or FCM provider push in this repository.
- Android uses local background notifications driven by periodic WorkManager wake-ups plus relay sync across all local device profiles.
- Notification payload generation happens on-device after sync and local decrypt (when preview mode allows it).
- Notification content is hidden by default and user-configurable.
- Current beta status: notification controls and sync plumbing are present, but delivery reliability still needs polish on some devices/background scheduling cases.

## Security and privacy boundary

- No plaintext message bodies are sent through third-party push payloads.
- Wake-up registration data on the relay is metadata-minimized and device-bound.
- If privacy mode is enabled, notifications default to hidden content unless explicitly overridden.
- Device revocation invalidates wake-up registration state for that device.

## Rule for future provider push

- Provider push payloads must remain minimal wake-up signals only.
- Message content must always be fetched from the relay and decrypted on-device.
- Sender/body preview must remain opt-in and privacy-first.
- Any provider push integration must ship with dedicated notification-privacy regression tests.
