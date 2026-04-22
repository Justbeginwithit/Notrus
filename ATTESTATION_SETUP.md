# Notrus Attestation Setup

This document defines the current relay attestation posture, what users see in clients, and how operators enable or enforce attestation verification.

## Current default state

By default, relay attestation verification is available but not configured/enforced.

Default relay env behavior in [server.js](server.js):

- `NOTRUS_ATTESTATION_ORIGIN=""`
- `NOTRUS_REQUIRE_ANDROID_ATTESTATION=false`
- `NOTRUS_REQUIRE_ANDROID_PLAY_INTEGRITY=false`
- `NOTRUS_REQUIRE_APPLE_DEVICECHECK=false`

With those defaults:

- `/api/health` returns `attestation.configured: false`
- registrations are accepted without mandatory third-party attestation verification
- relay still treats integrity as risk signals (not plaintext trust)

## What the client message means

If Android or macOS shows a message equivalent to “no relay attestation has been set up,” it means:

- the relay has no attestation verification endpoint configured (`NOTRUS_ATTESTATION_ORIGIN` unset), or
- attestation policy is not currently enforced.

This is a trust/abuse-control downgrade, not an automatic break of message-layer encryption.

## Enable attestation verification

Run the attestation service:

```bash
npm run start:attestation
```

Run relay with attestation origin:

```bash
NOTRUS_ATTESTATION_ORIGIN=http://127.0.0.1:3500 \
node server.js
```

## Enforce attestation policy

Enable strict enforcement as needed:

```bash
NOTRUS_ATTESTATION_ORIGIN=http://127.0.0.1:3500 \
NOTRUS_REQUIRE_ANDROID_ATTESTATION=true \
NOTRUS_REQUIRE_ANDROID_PLAY_INTEGRITY=true \
NOTRUS_REQUIRE_APPLE_DEVICECHECK=true \
node server.js
```

You can enable only selected requirements if your deployment scope is platform-specific.

## Verify runtime state

Check relay health:

```bash
curl -s http://127.0.0.1:3000/api/health
```

Relevant fields:

- `attestation.configured`
- `attestation.androidKeyAttestationRequired`
- `attestation.androidPlayIntegrityRequired`
- `attestation.appleDeviceCheckRequired`

Expected strict posture:

- `configured: true`
- required flags set to `true` for platforms you enforce

## Recommended beta operator posture

- keep attestation service online if you claim verified device posture
- enforce at least `NOTRUS_REQUIRE_ANDROID_ATTESTATION=true` for Android-focused deployments
- keep release notes honest about current enforcement choices
- verify with:
  - `npm run test:attestation-service`
  - `npm run test:attestation-enforcement`
