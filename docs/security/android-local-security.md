# Android Local Security

Android protects local Notrus material with platform-native storage.

## Storage

- StrongBox is preferred when available.
- Android Keystore is used as the fallback on devices without StrongBox support.
- The UI should show storage mode when possible.
- Local vault data should not be included in Android backups.

## Sensitive actions

Sensitive actions should use biometric or device-credential confirmation where available:

- Account export.
- Chat backup export.
- Account import.
- Chat backup restore.
- Account delete.
- Device revoke.
- Attachment export.
- Showing recovery material.
- Enabling full notification preview.
- Disabling privacy controls.

## Limits

StrongBox and Keystore protect keys at rest on normal devices. They do not protect plaintext while the device is compromised or while the user is actively viewing decrypted content.
