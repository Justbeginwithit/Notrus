# Known Security And Reliability Limitations

Current project label: beta.

## Security assurance

- Notrus is not independently audited.
- Scanner results must be refreshed for each release candidate.
- Emergency/high-risk readiness requires outside review and sustained real-world reliability evidence.

## Metadata

- The relay still sees some metadata, including timing, membership, and routing state.
- Notrus does not provide traffic-analysis resistance.
- Notrus does not provide anonymity.

## Messaging

- Direct messaging and group messaging have different security properties.
- Groups should not be described as equivalent to direct chats unless the exact group path is tested for the release.
- Groups currently support up to 32 members by default, with 3 to 12 members recommended for beta testing.
- Group device changes, account restores, and security-number changes must remain visible to users; they should not be treated as silent background repairs.
- Recovery and chat backup can change trust assumptions.
- Local message search is a planned local-only feature, not a relay-side plaintext search feature.
- Delete-for-everyone and message edit are not finished protocol features. Current local single-message deletion is local-only.

## Delivery

- Background notifications can be delayed by Android and network conditions.
- Relay downtime can interrupt send and sync.
- Users should keep a backup communication method for emergency situations.
- macOS local notifications require the app to still be running. They are not expected after full Quit/Command-Q in this build.
