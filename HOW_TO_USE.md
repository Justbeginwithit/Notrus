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

## Optional relay operator controls (disabled by default)

If you self-host and need operational cleanup tooling, enable the relay operator API:

```bash
NOTRUS_ENABLE_ADMIN_API=true \
NOTRUS_ADMIN_API_TOKEN="replace-with-long-random-token" \
node server.js
```

Call routes with header `X-Notrus-Admin-Token: <token>`:

- `GET /api/admin/users` for relay-wide account inspection
- `POST /api/admin/users/:userId/unblock` to reactivate a blocked/tombstoned account (and restore a username)
- `POST /api/admin/users/:userId/block` to deactivate/tombstone an account
- `POST /api/admin/users/:userId/delete` to hard-delete a relay account plus its threads

Or open the built-in GUI:

- `http://127.0.0.1:3000/admin`
- `https://<your-ngrok-or-domain>/admin`

Note: local profile lists in Android/macOS only show identities stored on that device, not all relay accounts.

Admin GUI capability boundary:

- can inspect/block/unblock/delete relay accounts
- cannot create users
- cannot decrypt message content
- cannot access local hardware-protected keys from client devices

See [ADMIN_GUI.md](ADMIN_GUI.md) for full details.

## 4. Build and install the clients

macOS:

- package with `npm run package:mac-app`
- open `dist/Notrus.app`

Android:

- package with `npm run package:android-app`
- install `dist/android/Notrus-0.3.4-beta5-release.apk`
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
- on Android, keep Reliable background delivery enabled if you want near-realtime background wake-ups; Android will show a persistent low-priority Notrus background delivery notification while the listener is active

## 7. Android background notifications

1. Open Settings > Notifications.
2. Turn Notifications on.
3. Grant Android notification permission when prompted.
4. Keep Notification content on Hidden unless you explicitly want sender or preview text.
5. Keep Reliable background delivery on for the best background behavior.

How it works:

- the foreground app uses authenticated relay events and silent sync
- the background app uses WorkManager plus an optional foreground service listener
- notification wake-ups never carry message plaintext
- the app syncs the relay and decrypts locally before it can show sender or preview text
- notification taps open the matching local conversation when the thread is still present

Limits:

- if Reliable background delivery is off, Android may delay polling
- if the app is force-stopped, Android will not deliver normal background work until the user opens it again
- OEM battery restrictions, denied notification permission, and data-saver policy can still delay notifications

## 8. Find contacts

Notrus discovery supports:

- username
- invite code

If search does not return a remote account:

1. verify both clients target the same relay
2. run sync on both clients
3. retry search by username or invite code

## 9. Start a direct chat

1. Search contact
2. Select result
3. Create thread
4. Send message

## 10. Group chats

Standards-group messaging is available with native MLS plus compatibility fanout support.

If a participant has no active MLS key package, clients can use standards-thread compatible fanout transport on the same thread protocol.

## 11. Account recovery and chat backup

Recover account:

1. Open Account Center
2. Export account recovery archive
3. Choose destination file
4. Protect file and passphrase

Import on replacement device:

1. Choose Recover account
2. Select archive
3. Enter archive passphrase
4. Complete local device setup

Restore chat history:

1. First recover or create the matching account locally
2. Choose Export chat backup on the old device
3. Use a separate strong backup passphrase
4. Choose Restore chat backup on the destination device
5. Enter the backup passphrase

Important:

- account recovery restores identity and future messaging continuity
- chat backup restores old local message history and cached decrypted messages
- chat backup does not include the account recovery secret
- chat backups are more sensitive than recovery archives because they contain message history
- attachment blobs are not silently bundled into account recovery

Recommended full migration flow:

1. On the old device, export account recovery.
2. On the old device, export encrypted chat backup with a separate backup passphrase.
3. On the new or reset device, import account recovery first.
4. Sync once and confirm the same username/account is active.
5. Restore encrypted chat backup second.
6. Sync both devices before sending new messages.

If a contact imported or reset their account:

1. Open Security.
2. Review the security-number change.
3. Verify the contact only after comparing the safety number out of band.
4. Sync once on both clients.
5. If sending still fails, use Reset secure session in that chat on the sender device, then sync both clients.

Do not repeatedly delete and recreate the conversation for identity-change recovery. Deleting local history is only for removing local messages from the device; it should not be used as the normal recovery path.

## 12. Common recovery actions

If transparency reports trust issues:

- reset transparency trust
- resync

If local vault breaks on a device:

- reset local vault
- import recovery archive

If messages become unreadable after an app update or account import:

- first sync both devices
- verify any pending security-number warning
- use Reset secure session from the affected direct chat
- sync both clients again
- only restore chat backup if local history itself is missing

If a chat was archived:

- open Archived
- choose Restore
- sync once
- the chat should stay in the normal Chats list after future syncs

If a restored chat jumps back into Archived after sync, update to a build newer than the archive-state persistence fix in the unreleased notes.

If device is lost:

- revoke linked device
- rotate or reset account state as needed

## 13. Current beta boundaries

Beta-ready:

- relay setup and sync
- local account creation
- recovery export/import
- username/invite discovery
- direct messaging between macOS and Android
- standards-group messaging with compatibility transport
- admin relay GUI for operator account cleanup and reactivation
- separate account recovery and encrypted chat backup flows
- Android background notification plumbing with hidden-default previews, WorkManager fallback, and optional reliable foreground delivery

Still required before stable:

- sustained multi-operator real-world burn-in
- external confidence boosters (independent review/audit, reproducibility maturity)
- Android notification delivery burn-in across broader OEM/device scheduling conditions
- broader burn-in for cross-device restored chat backups, especially mixed macOS/Android histories
