# macOS Local Security

macOS stores local Notrus material using platform-native protections and explicit profile portability choices.

## Profile modes

- Device-bound profile: recommended for stronger local protection.
- Portable recovery archive: deliberate transfer artifact with stronger warnings.
- Software-key or portable profile modes, if enabled, must be clearly labeled as weaker or more portable.

## Sensitive actions

Sensitive actions should require local authentication where available:

- Account export.
- Chat backup export.
- Account import.
- Chat backup restore.
- Account delete.
- Device revoke.
- Attachment export.
- Showing recovery material.
- Switching to a more portable profile mode.

## Plaintext lifecycle

Plaintext messages and attachments must not be logged. Temporary decrypted files should be minimized and cleaned. Notification previews should be hidden by default.
