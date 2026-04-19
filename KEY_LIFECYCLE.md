# Notrus Key Lifecycle

This document defines the owner, purpose, storage rule, rotation rule, recovery rule, and destruction rule for each key type used by the current production path in this repository.

The production path referenced here is:

- native macOS client in [`native/macos/NotrusMac`](native/macos/NotrusMac)
- strict relay policy in [`server.js`](server.js)
- standards core in [`native/protocol-core`](native/protocol-core)

## Scope notes

- Browser compatibility code still exists in the repository, but it is not the lifecycle reference for the production path.
- Notrus currently uses a single-device account policy for the production path. Additional devices are handled by importing a recovery archive and, when needed, publishing a recovery-authorized account reset.

## Key inventory

### Local vault master secret

- Owner: one macOS app installation on one Mac
- Purpose: wraps the encrypted identity catalog, contact-verification state, and thread-state sealing keys
- Storage: Keychain generic password with `ThisDeviceOnly` semantics and LocalAuthentication gating in [`DeviceSecretStore.swift`](native/macos/NotrusMac/Sources/DeviceSecretStore.swift)
- Exportability: not part of recovery archives and not synced through generic OS backup
- Rotation: implicit on first install; otherwise stable for the local vault lifetime
- Recovery: none; a new Mac must use an encrypted recovery archive instead
- Destruction: local profile deletion and app removal eliminate access to the vault-wrapped state on that device

### Recovery key

- Owner: one Notrus account
- Purpose: authorizes account reset after device loss or account migration
- Storage: inside the encrypted local identity catalog and explicit encrypted recovery archives
- Exportability: exportable only through deliberate recovery-archive creation
- Rotation: stable across account key resets unless a future manual recovery-key rotation flow is added
- Recovery: included in encrypted recovery archives
- Destruction: removed when a profile is deleted locally; a relay-side reset signed by this key replaces the old account identity material

### Signal identity key and session state

- Owner: one Notrus account on one device state snapshot
- Purpose: 1:1 identity binding, PQXDH session establishment, and Double Ratchet state
- Storage: encrypted local identity catalog plus encrypted thread-state store in [`IdentityStore.swift`](native/macos/NotrusMac/Sources/IdentityStore.swift) and [`ThreadStateStore.swift`](native/macos/NotrusMac/Sources/ThreadStateStore.swift)
- Exportability: included only in explicit encrypted recovery archives
- Rotation:
  - published Signal prekey bundle refreshes during registration in [`AppModel.swift`](native/macos/NotrusMac/Sources/AppModel.swift) and [`bridge.rs`](native/protocol-core/src/bridge.rs)
  - full Signal identity rotation through recovery-authorized account reset in [`AppModel.swift`](native/macos/NotrusMac/Sources/AppModel.swift) and [`server.js`](server.js)
- Recovery:
  - encrypted archive import restores the same state on a new Mac
  - recovery-authorized account reset publishes fresh public identity material when the old device should stop being trusted for future traffic
- Destruction:
  - deleting a local profile removes encrypted local state
  - verifying a changed contact key clears stale direct-session state through the standards core bridge before new trust is accepted

### MLS account key package state

- Owner: one Notrus account
- Purpose: RFC 9420 MLS credential and group state participation
- Storage: encrypted local identity catalog and thread-state store
- Exportability: explicit encrypted recovery archives only
- Rotation:
  - key package refresh on registration in [`AppModel.swift`](native/macos/NotrusMac/Sources/AppModel.swift)
  - full account reset publishes fresh MLS identity material
- Recovery: encrypted archive import or recovery-authorized account reset
- Destruction: local profile deletion removes local state; old group state is not silently resurrected because thread-state rollback is rejected

### Legacy native P-256 signing, encryption, and signed-prekey material

- Owner: one Notrus account
- Purpose: compatibility with legacy migration paths and relay compatibility fields
- Storage: encrypted local identity catalog
- Exportability: explicit recovery archives only
- Rotation: full account reset rotates them
- Recovery: encrypted recovery archives
- Destruction: local profile deletion and account reset replacement

### Thread-state sealing key

- Owner: one local identity on one Mac
- Purpose: encrypts and authenticates ratchet and group state snapshots at rest
- Storage: derived from the device-only vault master secret, never stored separately
- Exportability: not exported as a standalone key
- Rotation: implicit through device vault secret scope and monotonic generation advancement
- Recovery: restored indirectly by importing the encrypted account archive and unlocking the local vault
- Destruction: local profile deletion removes the encrypted thread-state file and resets the monotonic generation

## Rollback resistance

- Native thread-state snapshots carry a monotonic generation counter in [`ThreadStateStore.swift`](native/macos/NotrusMac/Sources/ThreadStateStore.swift).
- The latest accepted generation is stored separately in Keychain metadata through [`DeviceSecretStore.swift`](native/macos/NotrusMac/Sources/DeviceSecretStore.swift).
- If an attacker replays an older thread-state file, Notrus rejects it instead of reopening stale session state.

## Lost-device handling

Current product rule:

1. Import the encrypted recovery archive on a trusted Mac.
2. Use `Rotate Active Identity Keys` in the native app.
3. The app creates fresh public identity material and sends a recovery-authorized reset to the relay.
4. Contacts see a visible identity-key change event and must re-verify out of band.
5. Old direct-session state is cleared locally before trusting the new key.

This is the current single-device recovery model. It is not the final multi-device enrollment model described later in checklist item 13.

## Backup and recovery rules

- Generic OS backups are not trusted for current session state.
- Sensitive local directories are marked backup-excluded in [`SensitiveStoragePolicy.swift`](native/macos/NotrusMac/Sources/SensitiveStoragePolicy.swift).
- Recovery is deliberate and end-to-end encrypted through the archive flow in [`AccountPortability.swift`](native/macos/NotrusMac/Sources/AccountPortability.swift).
- The recovery archive is protected by a user-held passphrase and local device reauthentication.
