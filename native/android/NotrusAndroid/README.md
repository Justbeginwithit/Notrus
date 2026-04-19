# Notrus Android

`NotrusAndroid` is the native Android client for Notrus.

## Current Scope

- Android Keystore or StrongBox-aware profile creation
- encrypted local vault storage
- biometric/device-credential unlock
- relay registration and sync
- local saved contacts
- standards-based direct Signal chat support
- linked-device visibility and revocation
- multiple local profiles in one vault for testing and account switching

## Current Boundary

- direct chats follow the standards Signal path
- MLS groups are still on the native roadmap for full Android parity
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
