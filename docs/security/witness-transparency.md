# Witness Transparency

The Notrus witness is an independent observer for relay transparency state. It does not see message plaintext, attachment plaintext, private keys, local ratchet state, or recovery secrets.

## Current Public Deployment

Current public relay and witness origins:

```text
Relay origin:   https://relay.notrus.cloud
Witness origin: https://witness.notrus.cloud
```

Clients should use the witness origin above when they need a public witness that works from Android and macOS. A local witness origin such as `http://127.0.0.1:3400` only works on the same machine that runs the witness service.

## How It Works

1. The relay publishes signed transparency state at `/api/transparency`.
2. The witness polls the relay transparency endpoint.
3. The witness stores each observed relay transparency head over time.
4. Clients or operators can compare the current relay head with the witness-observed head.
5. A mismatch, rollback, missing signature, or unexpected signer change is treated as a trust signal that needs investigation.

The witness is intended to make key-directory rollback or equivocation more visible. It is not a replacement for end-to-end encryption, contact verification, local device security, or an external security audit.

## Operator Check Endpoints

Witness graphical console:

```text
https://witness.notrus.cloud/witness
```

The console shows public witness health and latest observed relay head without a token. Detailed history and read-only summary actions require `X-Notrus-Witness-Admin-Token`. If `WITNESS_ADMIN_TOKEN` is not configured, those history/admin endpoints fail closed.

Witness health:

```text
https://witness.notrus.cloud/api/witness/health
```

Latest observed relay transparency head:

```text
https://witness.notrus.cloud/api/witness/head?relayOrigin=https://relay.notrus.cloud
```

Observed witness history. This is a read-only operator endpoint and requires `X-Notrus-Witness-Admin-Token`:

```text
https://witness.notrus.cloud/api/witness/log?relayOrigin=https://relay.notrus.cloud
```

Read-only witness admin summary:

```text
https://witness.notrus.cloud/api/witness/admin/summary
```

Read-only witness admin history:

```text
https://witness.notrus.cloud/api/witness/admin/log?relayOrigin=https://relay.notrus.cloud
```

Relay transparency source:

```text
https://relay.notrus.cloud/api/transparency
```

## Healthy Output

A healthy witness head includes:

```json
{
  "latest": {
    "entryCount": 355,
    "observedAt": "2026-05-07T17:15:37.891Z",
    "relayOrigin": "https://relay.notrus.cloud",
    "transparencySignature": "base64-signature",
    "transparencySigner": {
      "algorithm": "ed25519",
      "keyId": "2986ea76487558e7a9c49dec"
    },
    "transparencyHead": "842c5b2abfae731e33564b850d43cc1f0c61423a4c44194df7b3a065219c1cf6"
  }
}
```

Normal behavior:

- `entryCount` increases when the relay records new identity, prekey, device, or security events.
- `transparencyHead` changes when `entryCount` increases.
- `transparencySignature` is present.
- `transparencySigner.keyId` stays stable unless the operator intentionally rotates the transparency signer.
- `latest` matches the newest entry in the witness history.

Example normal progression:

```text
entryCount 353 -> head cc615d...
entryCount 354 -> head 274f5b...
entryCount 355 -> head 842c5b...
```

## Warning Signs

Investigate if any of these happen:

- `entryCount` goes backwards.
- `transparencyHead` changes without a valid signature.
- `transparencySigner.keyId` changes unexpectedly.
- Different clients or witnesses see different heads for the same relay state.
- The witness cannot observe the relay for an extended period.
- The relay transparency endpoint and witness latest head disagree after normal polling delay.

An expected signer rotation should be documented before deployment, announced to users/operators, and checked carefully because clients may treat signer changes as a trust event.

## Local Run Commands

Start the witness locally:

```bash
RELAY_ORIGIN=https://relay.notrus.cloud \
WITNESS_ADMIN_TOKEN="replace-with-long-random-token" \
npm run start:witness
```

Default local witness origin:

```text
http://127.0.0.1:3400
```

For the current Cloudflare Tunnel deployment, the tunnel config routes:

```text
relay.notrus.cloud   -> 127.0.0.1:3000
witness.notrus.cloud -> 127.0.0.1:3400
```

Keep the Cloudflare Tunnel credentials and `/Users/tim/.cloudflared/config.yml` private on the deployment machine.
