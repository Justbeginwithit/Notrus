# Notrus

`Notrus` is the native Android client for this project.

## Current Scope

- Android Keystore or StrongBox-aware profile creation
- encrypted local vault storage
- biometric/device-credential unlock
- relay registration and sync
- local saved contacts
- standards-based direct Signal chat support
- encrypted mailbox attachment send + decrypt-and-save support on standards direct chats
- linked-device visibility and revocation
- multiple local profiles in one vault for testing and account switching

## Current Boundary

- direct chats follow the standards Signal path
- standards-group threads support compatible fanout transport on Android (per-recipient Signal envelopes inside `mls-rfc9420-v1` delivery)
- native MLS state processing still exists as a separate path in the protocol core and macOS client
- release packaging exists, but production signing and attestation rollout still need hardening work

## Build

From the repository root:

```bash
npm run build:android-app
```

Package APKs:

```bash
npm run package:android-app
```

Run connected tests:

```bash
cd native/android/NotrusAndroid
./gradlew connectedDebugAndroidTest
```
