# Notrus Device Model

## Shipping model

The current native clients now maintain a linked-device registry per account.

- each installation creates its own device-management key
- devices register themselves separately from thread membership
- linked devices are listed and revoked at the account layer
- recovery-authorized account reset revokes all linked devices at once

## What this means for security

- device add and revoke events are visible to the account owner
- group membership is not conflated with device membership
- a stolen laptop or phone can be evicted through linked-device revocation or full account reset
- macOS and Android now share the same linked-device relay contract

## Honest boundary

The linked-device control plane is now present, but full simultaneous multi-device messaging parity still depends on protocol-engine parity and portable state support on each platform. The relay and native clients can now distinguish, list, and revoke devices honestly; they do not yet claim a Signal-style production multi-device UX across every client surface.
