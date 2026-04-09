# How To Use Notrus

## 1. Start A Relay

From the repository root:

```bash
node server.js
```

For local development, use:

- `http://127.0.0.1:3000`
- `http://localhost:3000`

For remote device usage, use HTTPS.

## 2. Optional Witness

If you want an independent transparency observer:

```bash
RELAY_ORIGIN=http://127.0.0.1:3000 npm run start:witness
```

## 3. Install The Clients

macOS:

- package with `npm run package:mac-app`
- open `dist/NotrusMac.app`

Android:

- package with `npm run package:android-app`
- install `dist/android/NotrusAndroid-release.apk`

## 4. Create Or Import A Profile

On both clients you can either:

- create a new local identity
- import an existing recovery archive

Use recovery import if you are moving an existing account to a new device.

## 5. Point The Client At The Relay

Set the relay origin in the client to:

- your local relay URL for same-machine development
- your HTTPS relay URL for remote devices

If the relay transparency signer changed, use the client’s transparency reset action and resync.

## 6. Find Contacts

Notrus currently supports contact discovery by:

- username
- invite code

If search does not return a remote account immediately:

1. make sure both clients are using the same relay
2. refresh sync once
3. search again by username or invite code

## 7. Start A Direct Chat

Direct chats are the primary cross-platform path today.

1. search for the contact
2. select the result
3. create the thread
4. send a message

## 8. Group Chats

Group support exists in the codebase, but Android group parity is still incomplete.

Use direct chats as the stable cross-platform path unless you are explicitly testing current MLS group behavior.

## 9. Recovery Export And Import

Export from a trusted device:

1. open Account Center
2. export a recovery archive
3. choose a destination file
4. protect that file and its password

Import on a replacement device:

1. choose import
2. select the recovery archive
3. enter the archive password
4. complete local device setup

## 10. Common Recovery Actions

If the app reports a transparency problem:

- reset transparency trust
- resync

If the local vault is broken on a device:

- reset the local vault
- import a recovery archive

If a device is lost:

- revoke the linked device
- rotate or reset account state if needed

## 11. What To Expect In This Alpha

Stable enough to test:

- relay setup
- local account creation
- recovery export/import
- username or invite-code discovery
- direct messaging between macOS and Android

Still under active hardening:

- Android group parity
- production release signing and notarization
- attestation enforcement rollout
- external audit
