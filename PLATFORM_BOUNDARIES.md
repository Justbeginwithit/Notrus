# Notrus Platform Boundaries

This document defines which macOS integration surfaces are intentionally enabled for the current production path and which are intentionally absent.

## Enabled surfaces

- explicit recovery-archive import through `NSOpenPanel`
- explicit recovery-archive export through `NSSavePanel`
- direct relay networking through ATS-governed `URLSession`
- local device authentication through `LocalAuthentication`

## Intentionally absent surfaces

- push-notification delivery
- deep-link URL handlers
- document-open handlers
- clipboard integrations
- share-sheet integrations
- drag-and-drop import or export
- automatic attachment preview or Quick Look rendering

## Product rule

Any new app-entry or inter-app surface must be treated as untrusted input and added here with:

- the exact API surface
- the security purpose
- the validation rule
- the test or proof that constrains it

Until that happens, the surface should remain absent from the production app.
