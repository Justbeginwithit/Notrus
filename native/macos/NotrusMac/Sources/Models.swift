import Foundation

struct JWK: Codable, Hashable {
    let crv: String
    let kty: String
    let x: String
    let y: String
}

struct LocalIdentity: Codable, Equatable {
    let id: String
    let username: String
    let displayName: String
    let createdAt: String
    let storageMode: String?
    let fingerprint: String
    let recoveryFingerprint: String
    let recoveryPublicJwk: JWK
    let recoveryRepresentation: String
    let signingPublicJwk: JWK
    let signingRepresentation: String
    let encryptionPublicJwk: JWK
    let encryptionRepresentation: String
    let prekeyCreatedAt: String
    let prekeyFingerprint: String
    let prekeyPublicJwk: JWK
    let prekeyRepresentation: String
    let prekeySignature: String
    let standardsMlsKeyPackage: PublicMlsKeyPackage?
    let standardsMlsState: String?
    let standardsSignalBundle: PublicSignalBundle?
    let standardsSignalState: String?
}

extension LocalIdentity {
    enum CodingKeys: String, CodingKey {
        case id
        case username
        case displayName
        case createdAt
        case storageMode
        case fingerprint
        case recoveryFingerprint
        case recoveryPublicJwk
        case recoveryRepresentation
        case signingPublicJwk
        case signingRepresentation
        case encryptionPublicJwk
        case encryptionRepresentation
        case prekeyCreatedAt
        case prekeyFingerprint
        case prekeyPublicJwk
        case prekeyRepresentation
        case prekeySignature
        case standardsMlsKeyPackage
        case standardsMlsState
        case standardsSignalBundle
        case standardsSignalState
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let id = try container.decode(String.self, forKey: .id)
        let username = try container.decode(String.self, forKey: .username)
        let displayName = try container.decode(String.self, forKey: .displayName)
        let createdAt = try container.decode(String.self, forKey: .createdAt)
        let storageMode = try container.decodeIfPresent(String.self, forKey: .storageMode)
        let fingerprint = try container.decode(String.self, forKey: .fingerprint)
        let signingPublicJwk = try container.decode(JWK.self, forKey: .signingPublicJwk)
        let signingRepresentation = try container.decode(String.self, forKey: .signingRepresentation)
        let encryptionPublicJwk = try container.decode(JWK.self, forKey: .encryptionPublicJwk)
        let encryptionRepresentation = try container.decode(String.self, forKey: .encryptionRepresentation)
        let prekeyCreatedAt = try container.decodeIfPresent(String.self, forKey: .prekeyCreatedAt) ?? createdAt
        let prekeyFingerprint = try container.decodeIfPresent(String.self, forKey: .prekeyFingerprint) ?? fingerprint
        let prekeyPublicJwk = try container.decodeIfPresent(JWK.self, forKey: .prekeyPublicJwk) ?? encryptionPublicJwk
        let prekeyRepresentation = try container.decodeIfPresent(String.self, forKey: .prekeyRepresentation) ?? ""
        let prekeySignature = try container.decodeIfPresent(String.self, forKey: .prekeySignature) ?? ""
        let standardsMlsKeyPackage = try container.decodeIfPresent(PublicMlsKeyPackage.self, forKey: .standardsMlsKeyPackage)
        let standardsMlsState = try container.decodeIfPresent(String.self, forKey: .standardsMlsState)
        let standardsSignalBundle = try container.decodeIfPresent(PublicSignalBundle.self, forKey: .standardsSignalBundle)
        let standardsSignalState = try container.decodeIfPresent(String.self, forKey: .standardsSignalState)

        let recoveryRepresentation = try container.decodeIfPresent(String.self, forKey: .recoveryRepresentation) ?? signingRepresentation
        let recoveryPublicJwk = try container.decodeIfPresent(JWK.self, forKey: .recoveryPublicJwk) ?? signingPublicJwk
        let recoveryFingerprint = try container.decodeIfPresent(String.self, forKey: .recoveryFingerprint) ?? fingerprint

        self.init(
            id: id,
            username: username,
            displayName: displayName,
            createdAt: createdAt,
            storageMode: storageMode,
            fingerprint: fingerprint,
            recoveryFingerprint: recoveryFingerprint,
            recoveryPublicJwk: recoveryPublicJwk,
            recoveryRepresentation: recoveryRepresentation,
            signingPublicJwk: signingPublicJwk,
            signingRepresentation: signingRepresentation,
            encryptionPublicJwk: encryptionPublicJwk,
            encryptionRepresentation: encryptionRepresentation,
            prekeyCreatedAt: prekeyCreatedAt,
            prekeyFingerprint: prekeyFingerprint,
            prekeyPublicJwk: prekeyPublicJwk,
            prekeyRepresentation: prekeyRepresentation,
            prekeySignature: prekeySignature,
            standardsMlsKeyPackage: standardsMlsKeyPackage,
            standardsMlsState: standardsMlsState,
            standardsSignalBundle: standardsSignalBundle,
            standardsSignalState: standardsSignalState
        )
    }

    func updatingStandards(
        fingerprint: String? = nil,
        mlsKeyPackage: PublicMlsKeyPackage? = nil,
        mlsState: String? = nil,
        signalBundle: PublicSignalBundle? = nil,
        signalState: String? = nil
    ) -> LocalIdentity {
        LocalIdentity(
            id: id,
            username: username,
            displayName: displayName,
            createdAt: createdAt,
            storageMode: storageMode,
            fingerprint: fingerprint ?? self.fingerprint,
            recoveryFingerprint: recoveryFingerprint,
            recoveryPublicJwk: recoveryPublicJwk,
            recoveryRepresentation: recoveryRepresentation,
            signingPublicJwk: signingPublicJwk,
            signingRepresentation: signingRepresentation,
            encryptionPublicJwk: encryptionPublicJwk,
            encryptionRepresentation: encryptionRepresentation,
            prekeyCreatedAt: prekeyCreatedAt,
            prekeyFingerprint: prekeyFingerprint,
            prekeyPublicJwk: prekeyPublicJwk,
            prekeyRepresentation: prekeyRepresentation,
            prekeySignature: prekeySignature,
            standardsMlsKeyPackage: mlsKeyPackage ?? standardsMlsKeyPackage,
            standardsMlsState: mlsState ?? standardsMlsState,
            standardsSignalBundle: signalBundle ?? standardsSignalBundle,
            standardsSignalState: signalState ?? standardsSignalState
        )
    }

    var hasCompleteStandardsState: Bool {
        standardsMlsKeyPackage != nil &&
        standardsMlsState != nil &&
        standardsSignalBundle != nil &&
        standardsSignalState != nil
    }
}

struct IdentityCatalog: Codable, Equatable {
    let version: Int
    let activeIdentityId: String?
    let identities: [LocalIdentity]
}

struct IdentityCatalogEnvelope: Codable, Equatable {
    let version: Int
    let iv: String
    let ciphertext: String
}

struct PortableAccountArchive: Codable, Equatable {
    let version: Int
    let exportedAt: String
    let identity: LocalIdentity
    let threadRecords: [String: ThreadStoreRecord]
}

struct DeviceDescriptor: Codable, Hashable {
    let createdAt: String
    let id: String
    let label: String
    let platform: String
    let publicJwk: JWK
    let riskLevel: String
    let storageMode: String?
}

struct EncryptedPortableAccountArchive: Codable, Equatable {
    let version: Int
    let exportedAt: String
    let iv: String
    let salt: String
    let rounds: Int
    let ciphertext: String
}

struct RelayUser: Codable, Identifiable, Hashable {
    let id: String
    let username: String
    let displayName: String
    let directoryCode: String?
    let fingerprint: String
    let mlsKeyPackage: PublicMlsKeyPackage?
    let prekeyCreatedAt: String?
    let prekeyFingerprint: String?
    let prekeyPublicJwk: JWK?
    let prekeySignature: String?
    let signalBundle: PublicSignalBundle?
    let signingPublicJwk: JWK
    let encryptionPublicJwk: JWK
    let createdAt: String
    let updatedAt: String?

    init(
        id: String,
        username: String,
        displayName: String,
        directoryCode: String? = nil,
        fingerprint: String,
        mlsKeyPackage: PublicMlsKeyPackage? = nil,
        prekeyCreatedAt: String? = nil,
        prekeyFingerprint: String? = nil,
        prekeyPublicJwk: JWK? = nil,
        prekeySignature: String? = nil,
        signalBundle: PublicSignalBundle? = nil,
        signingPublicJwk: JWK,
        encryptionPublicJwk: JWK,
        createdAt: String,
        updatedAt: String? = nil
    ) {
        self.id = id
        self.username = username
        self.displayName = displayName
        self.directoryCode = directoryCode
        self.fingerprint = fingerprint
        self.mlsKeyPackage = mlsKeyPackage
        self.prekeyCreatedAt = prekeyCreatedAt
        self.prekeyFingerprint = prekeyFingerprint
        self.prekeyPublicJwk = prekeyPublicJwk
        self.prekeySignature = prekeySignature
        self.signalBundle = signalBundle
        self.signingPublicJwk = signingPublicJwk
        self.encryptionPublicJwk = encryptionPublicJwk
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

struct RelayLinkedDevice: Codable, Hashable, Identifiable {
    let createdAt: String
    let current: Bool
    let id: String
    let label: String
    let platform: String
    let revokedAt: String?
    let riskLevel: String
    let storageMode: String?
    let updatedAt: String
}

struct RelayDeviceEvent: Codable, Hashable, Identifiable {
    let actorDeviceId: String?
    let createdAt: String
    let deviceId: String
    let id: String
    let kind: String
    let label: String?
    let platform: String?
    let revokedAt: String?
}

struct PublicSignalBundle: Codable, Hashable {
    let deviceId: Int
    let identityKey: String
    let kyberPreKeyId: Int
    let kyberPreKeyPublic: String
    let kyberPreKeySignature: String
    let preKeyId: Int
    let preKeyPublic: String
    let registrationId: Int
    let signedPreKeyId: Int
    let signedPreKeyPublic: String
    let signedPreKeySignature: String
}

struct PublicMlsKeyPackage: Codable, Hashable {
    let ciphersuite: String
    let keyPackage: String
}

struct RelayMlsWelcomeEnvelope: Codable, Hashable {
    let toUserId: String
    let welcome: String
}

struct RelayMlsBootstrap: Codable, Hashable {
    let ciphersuite: String
    let groupId: String
    let welcomes: [RelayMlsWelcomeEnvelope]
}

struct RelayEnvelope: Codable, Hashable {
    let threadId: String
    let fromUserId: String
    let toUserId: String
    let createdAt: String
    let iv: String
    let ciphertext: String
    let signature: String
}

struct RelayEpochCommit: Codable, Hashable {
    let epoch: Int
    let envelopes: [RelayEnvelope]
}

struct RelayGroupState: Codable, Hashable {
    let epoch: Int
    let participantIds: [String]
    let transcriptHash: String
    let treeHash: String
}

struct RelayGroupCommit: Codable, Hashable {
    let addedIds: [String]
    let commitType: String?
    let committedAt: String?
    let committedBy: String?
    let envelopes: [RelayEnvelope]
    let epoch: Int
    let parentTranscriptHash: String
    let participantIds: [String]
    let removedIds: [String]
    let transcriptHash: String
    let treeHash: String
}

struct RelayMessage: Codable, Identifiable, Hashable {
    let id: String
    let senderId: String
    let threadId: String?
    let createdAt: String
    let iv: String?
    let ciphertext: String?
    let signature: String?
    let messageKind: String?
    let protocolField: String?
    let wireMessage: String?
    let counter: Int?
    let epoch: Int?
    let groupCommit: RelayGroupCommit?
    let paddingBucket: Int?
    let ratchetPublicJwk: JWK?

    enum CodingKeys: String, CodingKey {
        case id
        case senderId
        case threadId
        case createdAt
        case iv
        case ciphertext
        case signature
        case messageKind
        case protocolField = "protocol"
        case wireMessage
        case counter
        case epoch
        case groupCommit
        case paddingBucket
        case ratchetPublicJwk
    }
}

struct RelayThread: Codable, Identifiable, Hashable {
    let id: String
    let title: String
    let protocolField: String?
    let groupState: RelayGroupState?
    let initialRatchetPublicJwk: JWK?
    let mlsBootstrap: RelayMlsBootstrap?
    let createdAt: String
    let createdBy: String
    let participantIds: [String]
    let envelopes: [RelayEnvelope]
    let messages: [RelayMessage]

    enum CodingKeys: String, CodingKey {
        case id
        case title
        case protocolField = "protocol"
        case groupState
        case initialRatchetPublicJwk
        case mlsBootstrap
        case createdAt
        case createdBy
        case participantIds
        case envelopes
        case messages
    }
}

struct RelaySyncPayload: Codable {
    let deviceEvents: [RelayDeviceEvent]?
    let devices: [RelayLinkedDevice]?
    let entryCount: Int?
    let directoryDiscoveryMode: String?
    let relayTime: String?
    let transparencyEntries: [TransparencyEntry]?
    let transparencyHead: String?
    let transparencySignature: String?
    let transparencySigner: TransparencySignerInfo?
    let users: [RelayUser]
    let threads: [RelayThread]
}

struct DirectorySearchResponse: Codable {
    let mode: String?
    let query: String
    let results: [RelayUser]
}

struct TransparencyEntry: Codable, Hashable, Identifiable {
    var id: Int { sequence }

    let createdAt: String
    let entryHash: String
    let fingerprint: String
    let kind: String
    let prekeyFingerprint: String?
    let previousHash: String?
    let sequence: Int
    let userId: String
    let username: String
}

struct TransparencySignerInfo: Codable, Hashable {
    let algorithm: String
    let keyId: String
    let publicKeyRaw: String
    let publicKeySpki: String
}

struct RelayAbuseControls: Codable {
    let powDifficultyBits: Int?
    let powRequiredForRemoteUntrustedClients: Bool?
}

struct RelayHealth: Codable {
    let ok: Bool
    let abuseControls: RelayAbuseControls?
    let directoryDiscoveryMode: String?
    let protocolPolicy: ProtocolPolicySummary?
    let transparency: RelayTransparencyStatus?
    let serveClient: Bool?
    let users: Int
    let threads: Int
}

struct RelayTransparencyStatus: Codable, Hashable {
    let entryCount: Int?
    let signer: TransparencySignerInfo?
}

struct RegisterRequest: Codable {
    let device: DeviceDescriptor?
    let displayName: String
    let encryptionPublicJwk: JWK
    let fingerprint: String
    let mlsKeyPackage: PublicMlsKeyPackage?
    let prekeyCreatedAt: String
    let prekeyFingerprint: String
    let prekeyPublicJwk: JWK
    let prekeySignature: String
    let recoveryFingerprint: String
    let recoveryPublicJwk: JWK
    let signalBundle: PublicSignalBundle?
    let signingPublicJwk: JWK
    let userId: String
    let username: String
}

struct AccountResetRequest: Codable {
    let createdAt: String
    let device: DeviceDescriptor?
    let displayName: String
    let encryptionPublicJwk: JWK
    let fingerprint: String
    let mlsKeyPackage: PublicMlsKeyPackage?
    let prekeyCreatedAt: String
    let prekeyFingerprint: String
    let prekeyPublicJwk: JWK
    let prekeySignature: String
    let recoveryFingerprint: String
    let recoveryPublicJwk: JWK
    let recoverySignature: String
    let signalBundle: PublicSignalBundle?
    let signingPublicJwk: JWK
    let userId: String
    let username: String
}

struct AccountResetResponse: Codable {
    let deviceEvents: [RelayDeviceEvent]?
    let devices: [RelayLinkedDevice]?
    let ok: Bool
    let user: RelayUser
}

struct RegisterResponse: Codable {
    let deviceEvents: [RelayDeviceEvent]?
    let devices: [RelayLinkedDevice]?
    let user: RelayUser
}

struct DeviceRevokeRequest: Codable {
    let createdAt: String
    let signature: String
    let signerDeviceId: String
    let targetDeviceId: String
    let userId: String
}

struct DeviceRevokeResponse: Codable {
    let deviceEvents: [RelayDeviceEvent]
    let devices: [RelayLinkedDevice]
    let ok: Bool
    let revokedDeviceId: String
}

struct ThreadCreateRequest: Codable {
    let createdAt: String
    let createdBy: String
    let envelopes: [RelayEnvelope]
    let groupState: RelayGroupState?
    let id: String
    let initialRatchetPublicJwk: JWK?
    let mlsBootstrap: RelayMlsBootstrap?
    let participantIds: [String]
    let `protocol`: String
    let title: String
}

struct ThreadCreateResponse: Codable {
    let ok: Bool
    let threadId: String
}

struct MessagePostResponse: Codable {
    let ok: Bool
    let messageId: String
}

struct AttachmentUploadRequest: Codable, Hashable {
    let byteLength: Int
    let ciphertext: String
    let createdAt: String
    let id: String
    let iv: String
    let senderId: String
    let sha256: String
    let threadId: String
}

struct AttachmentUploadResponse: Codable {
    let ok: Bool
    let attachmentId: String
}

struct RelayAttachment: Codable, Hashable {
    let byteLength: Int
    let ciphertext: String
    let createdAt: String
    let id: String
    let iv: String
    let senderId: String
    let sha256: String
    let threadId: String
}

struct SecureAttachmentReference: Codable, Hashable, Identifiable {
    let id: String
    let attachmentKey: String
    let byteLength: Int
    let mediaType: String
    let fileName: String
    let sha256: String
}

struct OutboundMessage: Codable {
    let ciphertext: String?
    let counter: Int?
    let createdAt: String
    let epoch: Int?
    let groupCommit: RelayGroupCommit?
    let id: String
    let iv: String?
    let messageKind: String?
    let paddingBucket: Int?
    let protocolField: String?
    let ratchetPublicJwk: JWK?
    let senderId: String
    let signature: String?
    let threadId: String?
    let wireMessage: String?

    enum CodingKeys: String, CodingKey {
        case ciphertext
        case counter
        case createdAt
        case epoch
        case groupCommit
        case id
        case iv
        case messageKind
        case paddingBucket
        case protocolField = "protocol"
        case ratchetPublicJwk
        case senderId
        case signature
        case threadId
        case wireMessage
    }

    init(
        ciphertext: String? = nil,
        counter: Int? = nil,
        createdAt: String,
        epoch: Int? = nil,
        groupCommit: RelayGroupCommit? = nil,
        id: String,
        iv: String? = nil,
        messageKind: String? = nil,
        paddingBucket: Int? = nil,
        protocolField: String? = nil,
        ratchetPublicJwk: JWK? = nil,
        senderId: String,
        signature: String? = nil,
        threadId: String? = nil,
        wireMessage: String? = nil
    ) {
        self.ciphertext = ciphertext
        self.counter = counter
        self.createdAt = createdAt
        self.epoch = epoch
        self.groupCommit = groupCommit
        self.id = id
        self.iv = iv
        self.messageKind = messageKind
        self.paddingBucket = paddingBucket
        self.protocolField = protocolField
        self.ratchetPublicJwk = ratchetPublicJwk
        self.senderId = senderId
        self.signature = signature
        self.threadId = threadId
        self.wireMessage = wireMessage
    }
}

struct MessagePayload: Codable, Hashable {
    let attachments: [SecureAttachmentReference]
    let cover: Bool?
    let epochCommit: RelayEpochCommit?
    let padding: String?
    let text: String

    init(
        attachments: [SecureAttachmentReference] = [],
        cover: Bool? = nil,
        epochCommit: RelayEpochCommit? = nil,
        padding: String? = nil,
        text: String
    ) {
        self.attachments = attachments
        self.cover = cover
        self.epochCommit = epochCommit
        self.padding = padding
        self.text = text
    }
}

struct AbuseReportRequest: Codable, Hashable {
    let createdAt: String
    let messageIds: [String]
    let reason: String
    let reporterId: String
    let targetUserId: String
    let threadId: String?
}

struct AbuseReportResponse: Codable, Hashable {
    let ok: Bool
    let reportId: String
}

struct CachedMessageState: Codable, Hashable {
    let attachments: [SecureAttachmentReference]
    let body: String
    let hidden: Bool
    let status: String

    enum CodingKeys: String, CodingKey {
        case attachments
        case body
        case hidden
        case status
    }

    init(
        attachments: [SecureAttachmentReference] = [],
        body: String,
        hidden: Bool,
        status: String
    ) {
        self.attachments = attachments
        self.body = body
        self.hidden = hidden
        self.status = status
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        attachments = try container.decodeIfPresent([SecureAttachmentReference].self, forKey: .attachments) ?? []
        body = try container.decode(String.self, forKey: .body)
        hidden = try container.decodeIfPresent(Bool.self, forKey: .hidden) ?? false
        status = try container.decodeIfPresent(String.self, forKey: .status) ?? "ok"
    }
}

struct PairwiseThreadState: Codable, Hashable {
    var announceLocalRatchet: Bool
    var creatorId: String
    var localRatchetPrivateRepresentation: String?
    var localRatchetPublicJwk: JWK?
    var pendingSendRatchet: Bool
    var protocolField: String
    var receiveChainKey: String?
    var receiveCounter: Int
    var remoteRatchetPublicJwk: JWK?
    var rootKey: String
    var sendChainKey: String?
    var sendCounter: Int
    var skippedMessageKeys: [String: String]
    var threadId: String

    enum CodingKeys: String, CodingKey {
        case announceLocalRatchet
        case creatorId
        case localRatchetPrivateRepresentation = "localRatchetPrivateJwk"
        case localRatchetPublicJwk
        case pendingSendRatchet
        case protocolField = "protocol"
        case receiveChainKey
        case receiveCounter
        case remoteRatchetPublicJwk
        case rootKey
        case sendChainKey
        case sendCounter
        case skippedMessageKeys
        case threadId
    }

    init(
        announceLocalRatchet: Bool,
        creatorId: String,
        localRatchetPrivateRepresentation: String?,
        localRatchetPublicJwk: JWK?,
        pendingSendRatchet: Bool,
        protocolField: String,
        receiveChainKey: String?,
        receiveCounter: Int,
        remoteRatchetPublicJwk: JWK?,
        rootKey: String,
        sendChainKey: String?,
        sendCounter: Int,
        skippedMessageKeys: [String: String],
        threadId: String
    ) {
        self.announceLocalRatchet = announceLocalRatchet
        self.creatorId = creatorId
        self.localRatchetPrivateRepresentation = localRatchetPrivateRepresentation
        self.localRatchetPublicJwk = localRatchetPublicJwk
        self.pendingSendRatchet = pendingSendRatchet
        self.protocolField = protocolField
        self.receiveChainKey = receiveChainKey
        self.receiveCounter = receiveCounter
        self.remoteRatchetPublicJwk = remoteRatchetPublicJwk
        self.rootKey = rootKey
        self.sendChainKey = sendChainKey
        self.sendCounter = sendCounter
        self.skippedMessageKeys = skippedMessageKeys
        self.threadId = threadId
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        announceLocalRatchet = try container.decodeIfPresent(Bool.self, forKey: .announceLocalRatchet) ?? false
        creatorId = try container.decodeIfPresent(String.self, forKey: .creatorId) ?? ""
        localRatchetPrivateRepresentation = try container.decodeIfPresent(String.self, forKey: .localRatchetPrivateRepresentation)
        localRatchetPublicJwk = try container.decodeIfPresent(JWK.self, forKey: .localRatchetPublicJwk)
        pendingSendRatchet = try container.decodeIfPresent(Bool.self, forKey: .pendingSendRatchet) ?? false
        protocolField = try container.decodeIfPresent(String.self, forKey: .protocolField) ?? "pairwise-v2"
        receiveChainKey = try container.decodeIfPresent(String.self, forKey: .receiveChainKey)
        receiveCounter = try container.decodeIfPresent(Int.self, forKey: .receiveCounter) ?? 0
        remoteRatchetPublicJwk = try container.decodeIfPresent(JWK.self, forKey: .remoteRatchetPublicJwk)
        rootKey = try container.decodeIfPresent(String.self, forKey: .rootKey) ?? ""
        sendChainKey = try container.decodeIfPresent(String.self, forKey: .sendChainKey)
        sendCounter = try container.decodeIfPresent(Int.self, forKey: .sendCounter) ?? 0
        skippedMessageKeys = try container.decodeIfPresent([String: String].self, forKey: .skippedMessageKeys) ?? [:]
        threadId = try container.decodeIfPresent(String.self, forKey: .threadId) ?? ""
    }
}

struct GroupSenderState: Codable, Hashable {
    var chainKey: String
    var counter: Int
}

struct GroupTreeThreadState: Codable, Hashable {
    var currentEpoch: Int
    var epochMessageCount: Int
    var epochSecrets: [String: String]
    var memberIds: [String]
    var pendingCommit: RelayGroupCommit?
    var protocolField: String
    var senderStates: [String: GroupSenderState]
    var threadId: String
    var transcriptHash: String?
    var treeHash: String?

    enum CodingKeys: String, CodingKey {
        case currentEpoch
        case epochMessageCount
        case epochSecrets
        case memberIds
        case pendingCommit
        case protocolField = "protocol"
        case senderStates
        case threadId
        case transcriptHash
        case treeHash
    }

    init(
        currentEpoch: Int,
        epochMessageCount: Int,
        epochSecrets: [String: String],
        memberIds: [String],
        pendingCommit: RelayGroupCommit?,
        protocolField: String,
        senderStates: [String: GroupSenderState],
        threadId: String,
        transcriptHash: String?,
        treeHash: String?
    ) {
        self.currentEpoch = currentEpoch
        self.epochMessageCount = epochMessageCount
        self.epochSecrets = epochSecrets
        self.memberIds = memberIds
        self.pendingCommit = pendingCommit
        self.protocolField = protocolField
        self.senderStates = senderStates
        self.threadId = threadId
        self.transcriptHash = transcriptHash
        self.treeHash = treeHash
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        currentEpoch = try container.decodeIfPresent(Int.self, forKey: .currentEpoch) ?? 1
        epochMessageCount = try container.decodeIfPresent(Int.self, forKey: .epochMessageCount) ?? 0
        epochSecrets = try container.decodeIfPresent([String: String].self, forKey: .epochSecrets) ?? [:]
        memberIds = try container.decodeIfPresent([String].self, forKey: .memberIds) ?? []
        pendingCommit = try container.decodeIfPresent(RelayGroupCommit.self, forKey: .pendingCommit)
        protocolField = try container.decodeIfPresent(String.self, forKey: .protocolField) ?? "group-tree-v3"
        senderStates = try container.decodeIfPresent([String: GroupSenderState].self, forKey: .senderStates) ?? [:]
        threadId = try container.decodeIfPresent(String.self, forKey: .threadId) ?? ""
        transcriptHash = try container.decodeIfPresent(String.self, forKey: .transcriptHash)
        treeHash = try container.decodeIfPresent(String.self, forKey: .treeHash)
    }
}

struct ThreadStoreRecord: Codable, Hashable {
    var bootstrapState: PairwiseThreadState?
    var currentState: PairwiseThreadState?
    var groupTreeState: GroupTreeThreadState?
    var lastProcessedMessageId: String?
    var localTitle: String?
    var messageCache: [String: CachedMessageState]
    var pendingSentStates: [String: PairwiseThreadState]
    var processedMessageCount: Int
    var protocolField: String
    var standardsMlsThreadState: String?
    var standardsSignalPeerUserId: String?

    enum CodingKeys: String, CodingKey {
        case bootstrapState
        case currentState
        case groupTreeState = "state"
        case lastProcessedMessageId
        case localTitle
        case messageCache
        case pendingSentStates
        case processedMessageCount
        case protocolField = "protocol"
        case standardsMlsThreadState
        case standardsSignalPeerUserId
    }

    enum LegacyCodingKeys: String, CodingKey {
        case groupTreeState
    }

    init(
        bootstrapState: PairwiseThreadState? = nil,
        currentState: PairwiseThreadState? = nil,
        groupTreeState: GroupTreeThreadState? = nil,
        lastProcessedMessageId: String? = nil,
        localTitle: String? = nil,
        messageCache: [String: CachedMessageState] = [:],
        pendingSentStates: [String: PairwiseThreadState] = [:],
        processedMessageCount: Int = 0,
        protocolField: String,
        standardsMlsThreadState: String? = nil,
        standardsSignalPeerUserId: String? = nil
    ) {
        self.bootstrapState = bootstrapState
        self.currentState = currentState
        self.groupTreeState = groupTreeState
        self.lastProcessedMessageId = lastProcessedMessageId
        self.localTitle = localTitle
        self.messageCache = messageCache
        self.pendingSentStates = pendingSentStates
        self.processedMessageCount = processedMessageCount
        self.protocolField = protocolField
        self.standardsMlsThreadState = standardsMlsThreadState
        self.standardsSignalPeerUserId = standardsSignalPeerUserId
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let legacyContainer = try decoder.container(keyedBy: LegacyCodingKeys.self)
        let bootstrapState = try container.decodeIfPresent(PairwiseThreadState.self, forKey: .bootstrapState)
        let currentState = try container.decodeIfPresent(PairwiseThreadState.self, forKey: .currentState)
        let groupTreeState =
            try container.decodeIfPresent(GroupTreeThreadState.self, forKey: .groupTreeState)
            ?? legacyContainer.decodeIfPresent(GroupTreeThreadState.self, forKey: .groupTreeState)
        let messageCache = try container.decodeIfPresent([String: CachedMessageState].self, forKey: .messageCache) ?? [:]
        let processedMessageCount =
            try container.decodeIfPresent(Int.self, forKey: .processedMessageCount)
            ?? messageCache.count

        self.init(
            bootstrapState: bootstrapState,
            currentState: currentState,
            groupTreeState: groupTreeState,
            lastProcessedMessageId: try container.decodeIfPresent(String.self, forKey: .lastProcessedMessageId),
            localTitle: try container.decodeIfPresent(String.self, forKey: .localTitle),
            messageCache: messageCache,
            pendingSentStates: try container.decodeIfPresent([String: PairwiseThreadState].self, forKey: .pendingSentStates) ?? [:],
            processedMessageCount: processedMessageCount,
            protocolField: try container.decodeIfPresent(String.self, forKey: .protocolField)
                ?? groupTreeState?.protocolField
                ?? currentState?.protocolField
                ?? bootstrapState?.protocolField
                ?? "static-room-v1",
            standardsMlsThreadState: try container.decodeIfPresent(String.self, forKey: .standardsMlsThreadState),
            standardsSignalPeerUserId: try container.decodeIfPresent(String.self, forKey: .standardsSignalPeerUserId)
        )
    }
}

struct ThreadStoreEnvelope: Codable, Hashable {
    let ciphertext: String
    let generation: Int?
    let iv: String
    let version: Int
}

enum ContactTrustStatus: String, Codable, Hashable {
    case unverified
    case verified
    case changed
}

struct ContactTrustRecord: Codable, Hashable, Identifiable {
    var id: String { userId }

    let userId: String
    var username: String
    var displayName: String
    var observedFingerprint: String
    var trustedFingerprint: String
    var observedPrekeyFingerprint: String?
    var trustedPrekeyFingerprint: String?
    var firstSeenAt: String
    var lastSeenAt: String
    var lastVerifiedAt: String?
    var verificationMethod: String?
    var lastKeyChangeAt: String?
    var lastPrekeyRotationAt: String?
    var status: ContactTrustStatus
    var blockedAt: String? = nil
}

struct ContactSecurityEvent: Codable, Hashable, Identifiable {
    let id: String
    let userId: String
    let username: String
    let displayName: String
    let createdAt: String
    let kind: String
    let message: String
    let severity: String
    let requiresAction: Bool
    var dismissedAt: String?
    let observedFingerprint: String?
    let trustedFingerprint: String?
}

struct ContactSecurityState: Codable, Hashable {
    let version: Int
    var contacts: [String: ContactTrustRecord]
    var events: [ContactSecurityEvent]

    init(version: Int, contacts: [String: ContactTrustRecord], events: [ContactSecurityEvent]) {
        self.version = version
        self.contacts = contacts
        self.events = events
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        contacts = try container.decode([String: ContactTrustRecord].self, forKey: .contacts)
        events = try container.decodeIfPresent([ContactSecurityEvent].self, forKey: .events) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case version
        case contacts
        case events
    }
}

struct SecurityStateEnvelope: Codable, Hashable {
    let ciphertext: String
    let iv: String
    let version: Int
}

struct WitnessObservation: Hashable, Identifiable {
    var id: String { origin }

    let origin: String
    let entryCount: Int?
    let head: String?
    let observedAt: String?
    let status: String
}

struct TransparencyVerificationResult: Hashable {
    static let empty = TransparencyVerificationResult(
        chainValid: true,
        entries: [],
        head: nil,
        pinnedHead: nil,
        pinnedSignerKeyId: nil,
        signerKeyId: nil,
        warnings: [],
        witnesses: []
    )

    let chainValid: Bool
    let entries: [TransparencyEntry]
    let head: String?
    let pinnedHead: String?
    let pinnedSignerKeyId: String?
    let signerKeyId: String?
    let warnings: [String]
    let witnesses: [WitnessObservation]
}

struct ClientIntegrityReport: Codable, Hashable {
    let bundleIdentifier: String
    let codeSignatureStatus: String
    let deviceCheckStatus: String
    let deviceCheckTokenPresented: Bool
    let generatedAt: String
    let note: String?
    let riskLevel: String
}

struct DecryptedMessage: Identifiable, Hashable {
    let attachments: [SecureAttachmentReference]
    let id: String
    let senderId: String
    let senderName: String
    let createdAt: String
    let body: String
    let status: String

    init(
        attachments: [SecureAttachmentReference] = [],
        id: String,
        senderId: String,
        senderName: String,
        createdAt: String,
        body: String,
        status: String
    ) {
        self.attachments = attachments
        self.id = id
        self.senderId = senderId
        self.senderName = senderName
        self.createdAt = createdAt
        self.body = body
        self.status = status
    }
}

struct StandardsMessageEnvelope: Codable, Hashable {
    let attachments: [SecureAttachmentReference]
    let text: String
    let version: Int
}

struct LocalAttachmentDraft: Identifiable, Hashable {
    let id: String
    let byteLength: Int
    let fileName: String
    let mediaType: String
    let url: URL
}

struct ConversationThread: Identifiable, Hashable {
    let id: String
    let title: String
    let protocolLabel: String
    let participants: [RelayUser]
    let rawThread: RelayThread
    let messages: [DecryptedMessage]
    let warning: String?
    let supported: Bool
}

struct StandardsCreateIdentityResponse: Codable {
    let fingerprint: String
    let mlsKeyPackage: PublicMlsKeyPackage
    let mlsState: String
    let signalBundle: PublicSignalBundle
    let signalState: String
}

struct StandardsRefreshMlsKeyPackageResponse: Codable {
    let mlsKeyPackage: PublicMlsKeyPackage
    let mlsState: String
}

struct StandardsRefreshSignalBundleResponse: Codable {
    let signalBundle: PublicSignalBundle
    let signalState: String
}

struct StandardsSignalEncryptResponse: Codable {
    let localSignalState: String
    let messageKind: String
    let wireMessage: String
}

struct StandardsSignalDecryptResponse: Codable {
    let localSignalState: String
    let plaintext: String
}

struct StandardsSignalResetPeerResponse: Codable {
    let localSignalState: String
}

struct StandardsMlsCreateGroupResponse: Codable {
    let creatorMlsState: String
    let threadBootstrap: RelayMlsBootstrap
    let threadState: String
}

struct StandardsMlsJoinGroupResponse: Codable {
    let localMlsState: String
    let threadState: String
}

struct StandardsMlsEncryptMessageResponse: Codable {
    let localMlsState: String
    let threadState: String
    let wireMessage: String
}

struct StandardsMlsProcessMessageResponse: Codable {
    let localMlsState: String
    let plaintext: String
    let threadState: String
}
