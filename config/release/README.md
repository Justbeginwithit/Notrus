# Notrus Release Approvals

Production packaging requires an explicit two-person approval artifact.

1. Copy `approvals.template.json` to `approvals.json`.
2. Set `releaseId`, `commit`, and `initiatedBy`.
3. Add at least two unique entries in `approvals`.
4. Run production packaging with:

```bash
NOTRUS_RELEASE_MODE=production \
NOTRUS_RELEASE_APPROVALS_PATH=config/release/approvals.json \
zsh scripts/package-mac-app.sh
```

and

```bash
NOTRUS_RELEASE_MODE=production \
NOTRUS_RELEASE_APPROVALS_PATH=config/release/approvals.json \
zsh scripts/package-android-app.sh
```

The verifier is `scripts/verify-release-governance.mjs`.
