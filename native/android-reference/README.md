# Android Hardware-Backed Reference

This folder is a reference module for a native Android client that wants to keep Notrus identity keys in Android Keystore or StrongBox when available.

The shipping Notrus path for Android is a native client, not a compatibility wrapper around another surface.

The reference implementation in `NotrusStrongBoxIdentityProvider.kt` shows how to:

- generate a hardware-backed signing key
- generate a hardware-backed key-agreement key
- request StrongBox when the device supports it
- rotate a signed prekey
- sign the same prekey payload shape used by the relay

To turn this into a production Android client, you would still need:

- a full Android app project and Gradle setup
- transport code for the relay APIs
- the direct and group ratchet logic in Kotlin
- lifecycle and biometric policies for key access
- device compatibility handling when StrongBox is unavailable
