# Recovery And Backup

Notrus separates account recovery from chat-history backup.

## Account recovery

Account recovery restores account identity and future messaging continuity. It does not promise full readable chat-history restoration.

Recovery archives include account/recovery material and enough state to re-link the account safely. They must be encrypted, versioned, and imported only on trusted devices.

## Encrypted chat backup

Chat backup restores the past. It is more sensitive than account recovery because it can include local message history, session state, group state, attachment references, and cached plaintext needed for local history restoration.

Chat backups require a separate strong backup passphrase or backup key. Failed imports must not partially corrupt local chat state.

## User wording

- Recover account: restores identity and future messaging.
- Restore chat backup: restores old readable messages when the backup contains the required history state.

## Security boundary

Backup and recovery change the threat model. A stolen recovery archive or chat backup can be highly sensitive even when encrypted, especially if the passphrase is weak.
