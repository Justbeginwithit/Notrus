import Foundation

enum ProtocolPolicyMode: String, Codable, Hashable {
    case allowExperimental = "allow-experimental"
    case requireStandards = "require-standards"
}

struct ProtocolPolicySummary: Codable, Hashable {
    let label: String
    let mode: ProtocolPolicyMode
    let note: String
}

struct NotrusProtocolSpec: Hashable {
    let name: String
    let label: String
    let note: String
    let available: Bool
    let productionReady: Bool
    let standardTrack: Bool
}

enum NotrusProtocolCatalog {
    private static let unknownSpec = NotrusProtocolSpec(
        name: "unknown",
        label: "Unknown Protocol",
        note: "This client does not recognize the advertised protocol, so it cannot treat it as trusted or production-safe.",
        available: false,
        productionReady: false,
        standardTrack: false
    )

    private static let specs: [String: NotrusProtocolSpec] = [
        "static-room-v1": NotrusProtocolSpec(
            name: "static-room-v1",
            label: "Experimental Static Room v1",
            note: "Legacy wrapped-room-key thread. This is an Notrus-specific protocol and is not production-acceptable.",
            available: true,
            productionReady: false,
            standardTrack: false
        ),
        "pairwise-v2": NotrusProtocolSpec(
            name: "pairwise-v2",
            label: "Experimental Pairwise Ratchet",
            note: "Direct chats currently use an Notrus-specific protocol. The production migration target is PQXDH-style async setup plus Double Ratchet-style session evolution.",
            available: true,
            productionReady: false,
            standardTrack: false
        ),
        "group-epoch-v2": NotrusProtocolSpec(
            name: "group-epoch-v2",
            label: "Experimental Group Epoch v2",
            note: "This Notrus-specific group protocol is metadata-only in some clients and is not production-acceptable.",
            available: true,
            productionReady: false,
            standardTrack: false
        ),
        "group-tree-v3": NotrusProtocolSpec(
            name: "group-tree-v3",
            label: "Experimental Group Tree v3",
            note: "Groups currently use an Notrus-specific protocol. The production migration target is RFC 9420 MLS.",
            available: true,
            productionReady: false,
            standardTrack: false
        ),
        "signal-pqxdh-double-ratchet-v1": NotrusProtocolSpec(
            name: "signal-pqxdh-double-ratchet-v1",
            label: "PQXDH + Double Ratchet",
            note: "Production direct-message protocol using Signal-style asynchronous pre-key setup and Double Ratchet session evolution.",
            available: true,
            productionReady: true,
            standardTrack: true
        ),
        "mls-rfc9420-v1": NotrusProtocolSpec(
            name: "mls-rfc9420-v1",
            label: "MLS RFC 9420",
            note: "Production group-message protocol using RFC 9420 Messaging Layer Security.",
            available: true,
            productionReady: true,
            standardTrack: true
        )
    ]

    static func spec(for protocolName: String) -> NotrusProtocolSpec {
        specs[protocolName] ?? unknownSpec
    }

    static func chooseProtocol(participantCount: Int) -> String {
        if participantCount >= 3 {
            return "mls-rfc9420-v1"
        }
        if participantCount == 2 {
            return "signal-pqxdh-double-ratchet-v1"
        }
        return "static-room-v1"
    }

    static func allowed(_ protocolName: String, under policy: ProtocolPolicyMode) -> Bool {
        let spec = spec(for: protocolName)
        switch policy {
        case .requireStandards:
            return spec.standardTrack && spec.productionReady && spec.available
        case .allowExperimental:
            return spec.available
        }
    }

    static func summary(for policy: ProtocolPolicyMode) -> ProtocolPolicySummary {
        switch policy {
        case .requireStandards:
            return ProtocolPolicySummary(
                label: "Standards Required",
                mode: .requireStandards,
                note: "This client or relay only accepts production-grade standards-based protocols. New direct chats use PQXDH + Double Ratchet, and groups use RFC 9420 MLS."
            )
        case .allowExperimental:
            return ProtocolPolicySummary(
                label: "Experimental Allowed",
                mode: .allowExperimental,
                note: "This build still exposes Notrus experimental protocols for migration work, but new production conversations should use PQXDH + Double Ratchet or RFC 9420 MLS."
            )
        }
    }
}
