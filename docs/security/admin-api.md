# Relay Operator API

The relay operator API is an optional relay-operator tool. It is disabled by default and must not be treated as part of the normal user trust path.

Current hosted relay operator console:

```text
https://relay.notrus.cloud/admin
```

## Enablement

Admin routes require both:

- `NOTRUS_ENABLE_ADMIN_API=true`
- `NOTRUS_ADMIN_API_TOKEN` set to a long random token

Every operator request must include:

- `X-Notrus-Admin-Token: <token>`

Localhost, private IP addresses, and reverse-proxy headers never bypass this token requirement.

## Capabilities

- List relay users with minimized operational fields.
- Block a user account.
- Unblock a user account.
- Delete a user account and associated relay records.

## Non-capabilities

- No plaintext message access.
- No plaintext attachment access.
- No user backup export.
- No user impersonation.
- No user session issuance.

## Operator safety rules

- Keep the admin token outside the repository.
- Restrict network access to admin routes.
- Rotate the token after exposure.
- Document any operational use that affects user access.
