export const PROTOCOL_POLICY = Object.freeze({
  ALLOW_EXPERIMENTAL: "allow-experimental",
  REQUIRE_STANDARDS: "require-standards",
});

export const PROTOCOL_SPECS = Object.freeze({
  "static-room-v1": {
    available: true,
    label: "Experimental Static Room v1",
    note: "Legacy wrapped-room-key thread. Custom Notrus protocol. Not production-acceptable.",
    productionReady: false,
    standardTrack: false,
  },
  "pairwise-v2": {
    available: true,
    label: "Experimental Pairwise Ratchet",
    note: "Custom Notrus direct-message protocol. Intended migration target is PQXDH-style async setup plus Double Ratchet-style session evolution.",
    productionReady: false,
    standardTrack: false,
  },
  "group-epoch-v2": {
    available: true,
    label: "Experimental Group Epoch v2",
    note: "Custom Notrus group protocol. Not production-acceptable.",
    productionReady: false,
    standardTrack: false,
  },
  "group-tree-v3": {
    available: true,
    label: "Experimental Group Tree v3",
    note: "Custom Notrus group protocol. Intended migration target is RFC 9420 MLS.",
    productionReady: false,
    standardTrack: false,
  },
  "signal-pqxdh-double-ratchet-v1": {
    available: true,
    label: "PQXDH + Double Ratchet",
    note: "Production direct-message protocol using Signal-style asynchronous pre-key setup and Double Ratchet session evolution.",
    productionReady: true,
    standardTrack: true,
  },
  "mls-rfc9420-v1": {
    available: true,
    label: "MLS RFC 9420",
    note: "Production group-message protocol using RFC 9420 Messaging Layer Security.",
    productionReady: true,
    standardTrack: true,
  },
});

export function resolveProtocolPolicy(value) {
  return value === PROTOCOL_POLICY.ALLOW_EXPERIMENTAL
    ? PROTOCOL_POLICY.ALLOW_EXPERIMENTAL
    : PROTOCOL_POLICY.REQUIRE_STANDARDS;
}

export function getProtocolSpec(protocolName) {
  return PROTOCOL_SPECS[protocolName] ?? null;
}

export function protocolAllowedUnderPolicy(protocolName, policy) {
  const spec = getProtocolSpec(protocolName);
  if (!spec) {
    return false;
  }

  if (policy === PROTOCOL_POLICY.REQUIRE_STANDARDS) {
    return spec.standardTrack && spec.productionReady && spec.available;
  }

  return spec.available;
}

export function protocolPolicySummary(policy) {
  if (policy === PROTOCOL_POLICY.REQUIRE_STANDARDS) {
    return {
      label: "Standards Required",
      mode: PROTOCOL_POLICY.REQUIRE_STANDARDS,
      note: "This server only accepts production-grade standards-based protocols. Direct chats use PQXDH + Double Ratchet, and group chats use RFC 9420 MLS.",
    };
  }

  return {
    label: "Experimental Allowed",
    mode: PROTOCOL_POLICY.ALLOW_EXPERIMENTAL,
    note: "This server still allows Notrus experimental protocols for migration work, but the production path is PQXDH + Double Ratchet for direct chats and RFC 9420 MLS for groups.",
  };
}
