# How To Use Notrus

## 1. Start the relay

From the repository root:

```bash
node server.js
```

For local development, use:

- `http://127.0.0.1:3000`
- `http://localhost:3000`

For remote device usage, use HTTPS.

## 2. Optional witness

If you want an independent transparency observer:

```bash
RELAY_ORIGIN=http://127.0.0.1:3000 npm run start:witness
```

## 3. Recommended: configure attestation verification

Start attestation service:

```bash
npm run start:attestation
```

Run relay with attestation verification enabled:

```bash
NOTRUS_ATTESTATION_ORIGIN=http://127.0.0.1:3500 \
node server.js
```

Run relay with strict enforcement:

```bash
NOTRUS_ATTESTATION_ORIGIN=http://127.0.0.1:3500 \
NOTRUS_REQUIRE_ANDROID_ATTESTATION=true \
NOTRUS_REQUIRE_ANDROID_PLAY_INTEGRITY=true \
NOTRUS_REQUIRE_APPLE_DEVICECHECK=true \
node server.js
```

See full details in [ATTESTATION_SETUP.md](ATTESTATION_SETUP.md).

## 4. Build and install the clients

macOS:

- package with `npm run package:mac-app`
- open `dist/Notrus.app`

Android:

- package with `npm run package:android-app`
- install `dist/android/Notrus-0.3.1-beta2-release.apk`
  (or unversioned `dist/android/Notrus-release.apk`)

## 5. Create or import a profile

On both clients you can either:

- create a new local identity
- import an existing recovery archive

Use recovery import when moving an existing account to a new device.

## 6. Point each client at the relay

Set relay origin in client settings:

- local relay URL for same-machine development
- HTTPS relay URL for remote use

If transparency signer/trust state changed, use transparency reset and then resync.

Optional:

- enable privacy mode for randomized routine network delays
- keep privacy mode off for lowest latency during debugging

## 7. Find contacts

Notrus discovery supports:

- username
- invite code

If search does not return a remote account:

1. verify both clients target the same relay
2. run sync on both clients
3. retry search by username or invite code

## 8. Start a direct chat

1. Search contact
2. Select result
3. Create thread
4. Send message

## 9. Group chats

Standards-group messaging is available with native MLS plus compatibility fanout support.

If a participant has no active MLS key package, clients can use standards-thread compatible fanout transport on the same thread protocol.

## 10. Recovery export and import

Export from a trusted device:

1. Open Account Center
2. Export recovery archive
3. Choose destination file
4. Protect file and passphrase

Import on replacement device:

1. Choose import
2. Select archive
3. Enter archive passphrase
4. Complete local device setup

## 11. Common recovery actions

If transparency reports trust issues:

- reset transparency trust
- resync

If local vault breaks on a device:

- reset local vault
- import recovery archive

If device is lost:

- revoke linked device
- rotate or reset account state as needed

## 12. Current beta boundaries

Beta-ready:

- relay setup and sync
- local account creation
- recovery export/import
- username/invite discovery
- direct messaging between macOS and Android
- standards-group messaging with compatibility transport

Still required before stable:

- sustained multi-operator real-world burn-in
- external confidence boosters (independent review/audit, reproducibility maturity)
