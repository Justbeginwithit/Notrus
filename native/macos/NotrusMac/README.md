# Notrus

`Notrus` is the native macOS client for this project.

## Current Scope

- device-protected profile creation
- encrypted local account catalog and thread state
- LocalAuthentication-gated unlock and sensitive account actions
- contact verification and visible key-change events
- relay transparency verification and witness comparison
- standards-based direct Signal threads
- standards-based MLS group threads
- standards-group compatible fanout transport when participants do not expose native MLS key packages
- encrypted recovery archives and recovery-authorized account reset

## Run

From the repository root:

```bash
npm run start:mac-app
```

Build:

```bash
npm run build:mac-app
```

Package:

```bash
npm run package:mac-app
```

The native client allows local HTTP relay origins only for same-machine development. Non-local relay origins must use HTTPS.
