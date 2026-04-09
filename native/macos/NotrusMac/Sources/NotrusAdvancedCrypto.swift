import CryptoKit
import Foundation

enum NativeProtocolError: LocalizedError {
    case invalidPrekey
    case missingLocalBootstrap
    case missingRoomKey
    case missingSendChain
    case missingReceiveChain
    case missingLocalRatchet
    case staleSkippedKey
    case missingEpochSecret(Int)
    case missingEpochEnvelope
    case invalidTreeHash
    case invalidTranscriptContinuity
    case invalidTranscriptHash

    var errorDescription: String? {
        switch self {
        case .invalidPrekey:
            return "The signed prekey published for this contact could not be verified."
        case .missingLocalBootstrap:
            return "Local ratchet bootstrap state is missing on this Mac."
        case .missingRoomKey:
            return "This Mac could not unlock the room secret for the selected thread."
        case .missingSendChain:
            return "This thread does not currently have a sending chain."
        case .missingReceiveChain:
            return "This thread does not currently have a receiving chain."
        case .missingLocalRatchet:
            return "This Mac is missing the local ratchet step required to accept the new sending chain."
        case .staleSkippedKey:
            return "This Mac no longer has the skipped message key needed for that out-of-order message."
        case .missingEpochSecret(let epoch):
            return "The local epoch secret for group epoch \(epoch) is missing on this Mac."
        case .missingEpochEnvelope:
            return "This Mac is missing the epoch envelope required for the current group membership."
        case .invalidTreeHash:
            return "Group tree hash verification failed."
        case .invalidTranscriptContinuity:
            return "Group transcript continuity verification failed."
        case .invalidTranscriptHash:
            return "Group transcript hash verification failed."
        }
    }
}

extension NotrusCrypto {
    static func verifySignedPrekeyRecord(_ user: RelayUser) throws -> Bool {
        guard
            let prekeyPublicJwk = user.prekeyPublicJwk,
            let prekeySignature = user.prekeySignature,
            let prekeyCreatedAt = user.prekeyCreatedAt
        else {
            return false
        }

        let signingKey = try publicSigningKey(from: user.signingPublicJwk)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: base64Data(prekeySignature))
        return signingKey.isValidSignature(
            signature,
            for: Data(signedPrekeyPayload(createdAt: prekeyCreatedAt, prekeyPublicJwk: prekeyPublicJwk, userId: user.id).utf8)
        )
    }

    static func generateRatchetKeyPair() throws -> (privateKey: P256.KeyAgreement.PrivateKey, privateRepresentation: String, publicJwk: JWK) {
        let privateKey = P256.KeyAgreement.PrivateKey()
        return (
            privateKey: privateKey,
            privateRepresentation: privateKey.rawRepresentation.base64EncodedString(),
            publicJwk: try jwk(from: privateKey.publicKey.x963Representation)
        )
    }

    static func loadSoftwareKeyAgreementPrivateKey(_ representation: String) throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: base64Data(representation))
    }

    static func createPairwiseCreatorThreadState(
        creatorId: String,
        recipientId: String,
        recipientPrekeyPublicJwk: JWK,
        roomKey: Data,
        threadId: String
    ) throws -> PairwiseThreadState {
        let creatorRatchet = try generateRatchetKeyPair()
        let recipientPrekeyPublicKey = try publicKeyAgreementKey(from: recipientPrekeyPublicJwk)
        let sharedBits = sharedSecretData(try creatorRatchet.privateKey.sharedSecretFromKeyAgreement(with: recipientPrekeyPublicKey))
        let rootKeyBytes = deriveInitialRootBytes(roomKeyBytes: roomKey, dhBits: sharedBits, threadId: threadId)
        let sendChainKeyBytes = deriveInitialCreatorChain(
            rootKeyBytes: rootKeyBytes,
            threadId: threadId,
            creatorId: creatorId,
            recipientId: recipientId
        )

        return PairwiseThreadState(
            announceLocalRatchet: true,
            creatorId: creatorId,
            localRatchetPrivateRepresentation: creatorRatchet.privateRepresentation,
            localRatchetPublicJwk: creatorRatchet.publicJwk,
            pendingSendRatchet: false,
            protocolField: "pairwise-v2",
            receiveChainKey: nil,
            receiveCounter: 0,
            remoteRatchetPublicJwk: recipientPrekeyPublicJwk,
            rootKey: rootKeyBytes.base64EncodedString(),
            sendChainKey: sendChainKeyBytes.base64EncodedString(),
            sendCounter: 0,
            skippedMessageKeys: [:],
            threadId: threadId
        )
    }

    static func createPairwiseRecipientThreadState(
        creatorId: String,
        creatorRatchetPublicJwk: JWK,
        localUserId: String,
        recipientPrekeyRepresentation: String,
        roomKey: Data,
        threadId: String
    ) throws -> PairwiseThreadState {
        let creatorRatchetPublicKey = try publicKeyAgreementKey(from: creatorRatchetPublicJwk)
        let prekeyPrivateKey = try loadKeyAgreementPrivateKey(recipientPrekeyRepresentation)
        let sharedBits = sharedSecretData(try prekeyPrivateKey.sharedSecret(with: creatorRatchetPublicKey))
        let rootKeyBytes = deriveInitialRootBytes(roomKeyBytes: roomKey, dhBits: sharedBits, threadId: threadId)
        let receiveChainKeyBytes = deriveInitialCreatorChain(
            rootKeyBytes: rootKeyBytes,
            threadId: threadId,
            creatorId: creatorId,
            recipientId: localUserId
        )

        return PairwiseThreadState(
            announceLocalRatchet: false,
            creatorId: creatorId,
            localRatchetPrivateRepresentation: nil,
            localRatchetPublicJwk: nil,
            pendingSendRatchet: true,
            protocolField: "pairwise-v2",
            receiveChainKey: receiveChainKeyBytes.base64EncodedString(),
            receiveCounter: 0,
            remoteRatchetPublicJwk: creatorRatchetPublicJwk,
            rootKey: rootKeyBytes.base64EncodedString(),
            sendChainKey: nil,
            sendCounter: 0,
            skippedMessageKeys: [:],
            threadId: threadId
        )
    }

    static func sealPairwiseMessage(
        payload: MessagePayload,
        senderId: String,
        senderSigningRepresentation: String,
        threadId: String,
        threadState: PairwiseThreadState
    ) throws -> (message: OutboundMessage, nextState: PairwiseThreadState) {
        var nextState = threadState
        var announcedRatchetPublicJwk: JWK? = nil

        guard nextState.sendChainKey != nil || nextState.pendingSendRatchet else {
            throw NativeProtocolError.missingSendChain
        }

        if nextState.pendingSendRatchet {
            let ratchetStep = try advanceSendRatchet(nextState)
            nextState = ratchetStep.nextState
            announcedRatchetPublicJwk = ratchetStep.ratchetPublicJwk
        } else if nextState.announceLocalRatchet, let localRatchetPublicJwk = nextState.localRatchetPublicJwk {
            announcedRatchetPublicJwk = localRatchetPublicJwk
            nextState.announceLocalRatchet = false
        }

        let sendChainKey = try base64Data(nextState.sendChainKey ?? "")
        let step = deriveMessageStep(chainKeyBytes: sendChainKey)
        let createdAt = isoNow()
        let id = UUID().uuidString.lowercased()
        let iv = randomData(count: 12)
        let padded = try padPayload(payload)
        let messageKey = SymmetricKey(data: step.messageKeyBytes)
        let aad = Data(
            messageAad(
                threadId: threadId,
                id: id,
                senderId: senderId,
                createdAt: createdAt,
                protocolName: "pairwise-v2",
                counter: nextState.sendCounter,
                epoch: nil,
                groupCommit: nil,
                ratchetPublicJwk: announcedRatchetPublicJwk,
                paddingBucket: padded.paddingBucket
            ).utf8
        )
        let sealed = try AES.GCM.seal(
            padded.data,
            using: messageKey,
            nonce: .init(data: iv),
            authenticating: aad
        )
        let ciphertext = sealed.ciphertext + sealed.tag

        nextState.sendChainKey = step.nextChainKeyBytes.base64EncodedString()
        nextState.sendCounter += 1

        let signingKey = try loadSigningPrivateKey(senderSigningRepresentation)
        let signaturePayload = messageSignaturePayload(
            id: id,
            threadId: threadId,
            senderId: senderId,
            createdAt: createdAt,
            iv: iv.base64EncodedString(),
            ciphertext: ciphertext.base64EncodedString(),
            protocolName: "pairwise-v2",
            counter: nextState.sendCounter - 1,
            epoch: nil,
            groupCommit: nil,
            ratchetPublicJwk: announcedRatchetPublicJwk,
            paddingBucket: padded.paddingBucket
        )

        return (
            message: OutboundMessage(
                ciphertext: ciphertext.base64EncodedString(),
                counter: nextState.sendCounter - 1,
                createdAt: createdAt,
                epoch: nil,
                groupCommit: nil,
                id: id,
                iv: iv.base64EncodedString(),
                messageKind: nil,
                paddingBucket: padded.paddingBucket,
                protocolField: "pairwise-v2",
                ratchetPublicJwk: announcedRatchetPublicJwk,
                senderId: senderId,
                signature: try signText(signingKey, text: signaturePayload),
                threadId: threadId,
                wireMessage: nil
            ),
            nextState: nextState
        )
    }

    static func openPairwiseMessage(
        message: RelayMessage,
        senderSigningPublicJwk: JWK,
        threadState: PairwiseThreadState
    ) throws -> (nextState: PairwiseThreadState, payload: MessagePayload) {
        var nextState = threadState
        try verifyMessageSignature(message: message, senderSigningPublicJwk: senderSigningPublicJwk)

        if
            let advertisedRatchet = message.ratchetPublicJwk,
            advertisedRatchet != nextState.remoteRatchetPublicJwk
        {
            guard let localRatchetPrivateRepresentation = nextState.localRatchetPrivateRepresentation else {
                throw NativeProtocolError.missingLocalRatchet
            }

            let localRatchetPrivateKey = try loadSoftwareKeyAgreementPrivateKey(localRatchetPrivateRepresentation)
            let remoteRatchetPublicKey = try publicKeyAgreementKey(from: advertisedRatchet)
            let sharedBits = sharedSecretData(try localRatchetPrivateKey.sharedSecretFromKeyAgreement(with: remoteRatchetPublicKey))
            let rootStep = deriveRootStep(rootKeyBytes: try base64Data(nextState.rootKey), dhBits: sharedBits)

            nextState.remoteRatchetPublicJwk = advertisedRatchet
            nextState.rootKey = rootStep.rootKeyBytes.base64EncodedString()
            nextState.receiveChainKey = rootStep.chainKeyBytes.base64EncodedString()
            nextState.receiveCounter = 0
            nextState.pendingSendRatchet = true
        }

        guard let receiveChainKey = nextState.receiveChainKey else {
            throw NativeProtocolError.missingReceiveChain
        }

        let counter = message.counter ?? 0
        var messageKeyBytes = try takeSkippedMessageKey(&nextState, publicJwk: nextState.remoteRatchetPublicJwk, counter: counter)

        if messageKeyBytes == nil {
            var currentCounter = nextState.receiveCounter
            var currentChainKeyBytes = try base64Data(receiveChainKey)

            if counter < currentCounter {
                throw NativeProtocolError.staleSkippedKey
            }

            while currentCounter < counter {
                let skipped = deriveMessageStep(chainKeyBytes: currentChainKeyBytes)
                try cacheSkippedMessageKey(
                    &nextState,
                    publicJwk: nextState.remoteRatchetPublicJwk,
                    counter: currentCounter,
                    messageKeyBytes: skipped.messageKeyBytes
                )
                currentChainKeyBytes = skipped.nextChainKeyBytes
                currentCounter += 1
            }

            let currentStep = deriveMessageStep(chainKeyBytes: currentChainKeyBytes)
            messageKeyBytes = currentStep.messageKeyBytes
            nextState.receiveChainKey = currentStep.nextChainKeyBytes.base64EncodedString()
            nextState.receiveCounter = currentCounter + 1
        }

        let payload = try openPayload(message: message, messageKeyBytes: messageKeyBytes!)
        return (nextState: nextState, payload: payload)
    }

    static func createGroupTreeThreadState(
        participantIds: [String],
        roomKey: Data,
        startingEpoch: Int = 1,
        threadId: String,
        transcriptHash: String? = nil,
        treeHash: String? = nil
    ) throws -> GroupTreeThreadState {
        let resolvedTreeHash = treeHash ?? computeGroupTreeHash(epoch: startingEpoch, participantIds: participantIds, threadId: threadId)
        let resolvedTranscriptHash = transcriptHash ??
            computeGroupGenesisTranscriptHash(participantIds: participantIds, threadId: threadId, treeHash: resolvedTreeHash)

        return GroupTreeThreadState(
            currentEpoch: startingEpoch,
            epochMessageCount: 0,
            epochSecrets: [String(startingEpoch): roomKey.base64EncodedString()],
            memberIds: participantIds,
            pendingCommit: nil,
            protocolField: "group-tree-v3",
            senderStates: [:],
            threadId: threadId,
            transcriptHash: resolvedTranscriptHash,
            treeHash: resolvedTreeHash
        )
    }

    static func stageNextGroupTreeCommit(
        committedAt: String,
        committedBy: String,
        nextEpochRoomKey: Data,
        participantIds: [String],
        threadState: GroupTreeThreadState
    ) throws -> (groupCommit: RelayGroupCommit, nextState: GroupTreeThreadState) {
        var nextState = threadState
        let nextEpoch = nextState.currentEpoch + 1
        let previousMembers = nextState.memberIds
        let addedIds = participantIds.filter { !previousMembers.contains($0) }
        let removedIds = previousMembers.filter { !participantIds.contains($0) }
        let commitType = (addedIds.isEmpty && removedIds.isEmpty) ? "rotate" : "membership"
        let treeHash = computeGroupTreeHash(epoch: nextEpoch, participantIds: participantIds, threadId: nextState.threadId)
        let parentTranscriptHash = nextState.transcriptHash ??
            computeGroupGenesisTranscriptHash(
                participantIds: previousMembers,
                threadId: nextState.threadId,
                treeHash: nextState.treeHash ?? treeHash
            )
        let transcriptHash = computeGroupTranscriptHash(
            addedIds: addedIds,
            commitType: commitType,
            committedAt: committedAt,
            committedBy: committedBy,
            epoch: nextEpoch,
            parentTranscriptHash: parentTranscriptHash,
            participantIds: participantIds,
            removedIds: removedIds,
            threadId: nextState.threadId,
            treeHash: treeHash
        )

        let groupCommit = RelayGroupCommit(
            addedIds: addedIds,
            commitType: commitType,
            committedAt: committedAt,
            committedBy: committedBy,
            envelopes: [],
            epoch: nextEpoch,
            parentTranscriptHash: parentTranscriptHash,
            participantIds: participantIds,
            removedIds: removedIds,
            transcriptHash: transcriptHash,
            treeHash: treeHash
        )

        nextState.epochSecrets[String(nextEpoch)] = nextEpochRoomKey.base64EncodedString()
        nextState.pendingCommit = groupCommit

        return (groupCommit: groupCommit, nextState: nextState)
    }

    static func sealGroupTreeMessage(
        payload: MessagePayload,
        senderId: String,
        senderSigningRepresentation: String,
        threadId: String,
        threadState: GroupTreeThreadState,
        groupCommit: RelayGroupCommit?
    ) throws -> (message: OutboundMessage, nextState: GroupTreeThreadState) {
        var nextState = threadState
        let epoch = nextState.currentEpoch
        var senderState = try ensureGroupSenderState(&nextState, epoch: epoch, senderId: senderId)
        let step = deriveMessageStep(chainKeyBytes: try base64Data(senderState.chainKey))
        let createdAt = isoNow()
        let id = UUID().uuidString.lowercased()
        let iv = randomData(count: 12)
        let padded = try padPayload(payload)
        let messageKey = SymmetricKey(data: step.messageKeyBytes)
        let aad = Data(
            messageAad(
                threadId: threadId,
                id: id,
                senderId: senderId,
                createdAt: createdAt,
                protocolName: "group-tree-v3",
                counter: senderState.counter,
                epoch: epoch,
                groupCommit: groupCommit,
                ratchetPublicJwk: nil,
                paddingBucket: padded.paddingBucket
            ).utf8
        )
        let sealed = try AES.GCM.seal(
            padded.data,
            using: messageKey,
            nonce: .init(data: iv),
            authenticating: aad
        )
        let ciphertext = sealed.ciphertext + sealed.tag
        senderState.chainKey = step.nextChainKeyBytes.base64EncodedString()
        senderState.counter += 1
        nextState.senderStates[groupSenderStateKey(epoch: epoch, senderId: senderId)] = senderState

        if let groupCommit, nextState.pendingCommit?.epoch == groupCommit.epoch {
            nextState.currentEpoch = groupCommit.epoch
            nextState.epochMessageCount = 0
            nextState.memberIds = groupCommit.participantIds
            nextState.transcriptHash = groupCommit.transcriptHash
            nextState.treeHash = groupCommit.treeHash
            nextState.pendingCommit = nil
        } else {
            nextState.epochMessageCount += 1
        }

        let signingKey = try loadSigningPrivateKey(senderSigningRepresentation)
        let signaturePayload = messageSignaturePayload(
            id: id,
            threadId: threadId,
            senderId: senderId,
            createdAt: createdAt,
            iv: iv.base64EncodedString(),
            ciphertext: ciphertext.base64EncodedString(),
            protocolName: "group-tree-v3",
            counter: senderState.counter - 1,
            epoch: epoch,
            groupCommit: groupCommit,
            ratchetPublicJwk: nil,
            paddingBucket: padded.paddingBucket
        )

        return (
            message: OutboundMessage(
                ciphertext: ciphertext.base64EncodedString(),
                counter: senderState.counter - 1,
                createdAt: createdAt,
                epoch: epoch,
                groupCommit: groupCommit,
                id: id,
                iv: iv.base64EncodedString(),
                messageKind: nil,
                paddingBucket: padded.paddingBucket,
                protocolField: "group-tree-v3",
                ratchetPublicJwk: nil,
                senderId: senderId,
                signature: try signText(signingKey, text: signaturePayload),
                threadId: threadId,
                wireMessage: nil
            ),
            nextState: nextState
        )
    }

    static func openGroupTreeMessage(
        message: RelayMessage,
        recipientEncryptionRepresentation: String,
        senderEncryptionPublicJwk: JWK,
        senderSigningPublicJwk: JWK,
        threadState: GroupTreeThreadState,
        userId: String
    ) throws -> (nextState: GroupTreeThreadState, payload: MessagePayload) {
        var nextState = threadState
        try verifyMessageSignature(message: message, senderSigningPublicJwk: senderSigningPublicJwk)

        let epoch = message.epoch ?? 1
        var senderState = try ensureGroupSenderState(&nextState, epoch: epoch, senderId: message.senderId)
        var currentCounter = senderState.counter
        var currentChainKeyBytes = try base64Data(senderState.chainKey)

        if (message.counter ?? 0) < currentCounter {
            throw NativeProtocolError.staleSkippedKey
        }

        while currentCounter < (message.counter ?? 0) {
            let skipped = deriveMessageStep(chainKeyBytes: currentChainKeyBytes)
            currentChainKeyBytes = skipped.nextChainKeyBytes
            currentCounter += 1
        }

        let currentStep = deriveMessageStep(chainKeyBytes: currentChainKeyBytes)
        senderState.chainKey = currentStep.nextChainKeyBytes.base64EncodedString()
        senderState.counter = currentCounter + 1
        nextState.senderStates[groupSenderStateKey(epoch: epoch, senderId: message.senderId)] = senderState

        let payload = try openPayload(message: message, messageKeyBytes: currentStep.messageKeyBytes)
        if let groupCommit = message.groupCommit {
            let expectedTreeHash = computeGroupTreeHash(
                epoch: groupCommit.epoch,
                participantIds: groupCommit.participantIds,
                threadId: nextState.threadId
            )
            guard groupCommit.treeHash == expectedTreeHash else {
                throw NativeProtocolError.invalidTreeHash
            }

            let expectedParentTranscriptHash = nextState.transcriptHash ??
                computeGroupGenesisTranscriptHash(
                    participantIds: nextState.memberIds.isEmpty ? groupCommit.participantIds : nextState.memberIds,
                    threadId: nextState.threadId,
                    treeHash: nextState.treeHash ?? expectedTreeHash
                )
            guard groupCommit.parentTranscriptHash == expectedParentTranscriptHash else {
                throw NativeProtocolError.invalidTranscriptContinuity
            }

            let expectedTranscriptHash = computeGroupTranscriptHash(
                addedIds: groupCommit.addedIds,
                commitType: groupCommit.commitType ?? "rotate",
                committedAt: groupCommit.committedAt ?? message.createdAt,
                committedBy: groupCommit.committedBy ?? message.senderId,
                epoch: groupCommit.epoch,
                parentTranscriptHash: groupCommit.parentTranscriptHash,
                participantIds: groupCommit.participantIds,
                removedIds: groupCommit.removedIds,
                threadId: nextState.threadId,
                treeHash: groupCommit.treeHash
            )
            guard groupCommit.transcriptHash == expectedTranscriptHash else {
                throw NativeProtocolError.invalidTranscriptHash
            }

            if groupCommit.participantIds.contains(userId) {
                guard let envelope = groupCommit.envelopes.first(where: { $0.toUserId == userId }) else {
                    throw NativeProtocolError.missingEpochEnvelope
                }

                let epochKey = try unwrapRoomKeyEnvelope(
                    envelope: envelope,
                    recipientEncryptionRepresentation: recipientEncryptionRepresentation,
                    senderEncryptionPublicJwk: senderEncryptionPublicJwk,
                    senderSigningPublicJwk: senderSigningPublicJwk
                )
                nextState.epochSecrets[String(groupCommit.epoch)] = epochKey.base64EncodedString()
            }

            nextState.currentEpoch = groupCommit.epoch
            nextState.epochMessageCount = 0
            nextState.memberIds = groupCommit.participantIds
            nextState.transcriptHash = groupCommit.transcriptHash
            nextState.treeHash = groupCommit.treeHash
            nextState.pendingCommit = nil
        } else {
            nextState.currentEpoch = max(nextState.currentEpoch, epoch)
            nextState.epochMessageCount += 1
        }

        return (nextState: nextState, payload: payload)
    }

    static func createRotatedGroupCommit(
        createdAt: String,
        committedBy: String,
        participantIds: [String],
        senderEncryptionRepresentation: String,
        senderSigningRepresentation: String,
        threadId: String,
        threadState: GroupTreeThreadState,
        usersById: [String: RelayUser]
    ) throws -> (groupCommit: RelayGroupCommit, nextState: GroupTreeThreadState) {
        let nextEpochKey = randomRoomKey()
        var staged = try stageNextGroupTreeCommit(
            committedAt: createdAt,
            committedBy: committedBy,
            nextEpochRoomKey: nextEpochKey,
            participantIds: participantIds,
            threadState: threadState
        )
        let commitThreadId = "\(threadId):epoch:\(staged.groupCommit.epoch)"
        let envelopes = try participantIds.map { participantId in
            guard let participant = usersById[participantId] else {
                throw RelayClientError.requestFailed("A participant selected for the next group epoch no longer exists on the relay.")
            }

            return try wrapRoomKeyForRecipient(
                createdAt: createdAt,
                fromUserId: committedBy,
                recipientEncryptionPublicJwk: participant.encryptionPublicJwk,
                roomKey: nextEpochKey,
                senderEncryptionRepresentation: senderEncryptionRepresentation,
                senderSigningRepresentation: senderSigningRepresentation,
                threadId: commitThreadId,
                toUserId: participantId
            )
        }

        let populatedCommit = RelayGroupCommit(
            addedIds: staged.groupCommit.addedIds,
            commitType: staged.groupCommit.commitType,
            committedAt: staged.groupCommit.committedAt,
            committedBy: staged.groupCommit.committedBy,
            envelopes: envelopes,
            epoch: staged.groupCommit.epoch,
            parentTranscriptHash: staged.groupCommit.parentTranscriptHash,
            participantIds: staged.groupCommit.participantIds,
            removedIds: staged.groupCommit.removedIds,
            transcriptHash: staged.groupCommit.transcriptHash,
            treeHash: staged.groupCommit.treeHash
        )
        staged.nextState.pendingCommit = populatedCommit
        return (groupCommit: populatedCommit, nextState: staged.nextState)
    }

    static func protocolLabel(_ protocolName: String) -> String {
        NotrusProtocolCatalog.spec(for: protocolName).label
    }

    private static func verifyMessageSignature(message: RelayMessage, senderSigningPublicJwk: JWK) throws {
        guard
            let signaturePayload = message.signature,
            let ivPayload = message.iv,
            let ciphertextPayload = message.ciphertext
        else {
            throw NotrusCryptoError.invalidMessageSignature
        }
        let signingPublicKey = try publicSigningKey(from: senderSigningPublicJwk)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: base64Data(signaturePayload))
        let payload = messageSignaturePayload(
            id: message.id,
            threadId: message.threadId ?? "",
            senderId: message.senderId,
            createdAt: message.createdAt,
            iv: ivPayload,
            ciphertext: ciphertextPayload,
            protocolName: message.protocolField ?? "static-room-v1",
            counter: message.counter,
            epoch: message.epoch,
            groupCommit: message.groupCommit,
            ratchetPublicJwk: message.ratchetPublicJwk,
            paddingBucket: message.paddingBucket
        )
        guard signingPublicKey.isValidSignature(signature, for: Data(payload.utf8)) else {
            throw NotrusCryptoError.invalidMessageSignature
        }
    }

    private static func openPayload(message: RelayMessage, messageKeyBytes: Data) throws -> MessagePayload {
        guard let ciphertextPayload = message.ciphertext, let ivPayload = message.iv else {
            throw NotrusCryptoError.malformedCiphertext
        }
        let ciphertextWithTag = try base64Data(ciphertextPayload)
        guard ciphertextWithTag.count >= 16 else {
            throw NotrusCryptoError.malformedCiphertext
        }

        let sealedBox = try AES.GCM.SealedBox(
            nonce: .init(data: try base64Data(ivPayload)),
            ciphertext: ciphertextWithTag.prefix(ciphertextWithTag.count - 16),
            tag: ciphertextWithTag.suffix(16)
        )
        let plaintext = try AES.GCM.open(
            sealedBox,
            using: SymmetricKey(data: messageKeyBytes),
            authenticating: Data(
                messageAad(
                    threadId: message.threadId ?? "",
                    id: message.id,
                    senderId: message.senderId,
                    createdAt: message.createdAt,
                    protocolName: message.protocolField ?? "static-room-v1",
                    counter: message.counter,
                    epoch: message.epoch,
                    groupCommit: message.groupCommit,
                    ratchetPublicJwk: message.ratchetPublicJwk,
                    paddingBucket: message.paddingBucket
                ).utf8
            )
        )

        var payload = try JSONDecoder().decode(MessagePayload.self, from: plaintext)
        payload = MessagePayload(cover: payload.cover, epochCommit: payload.epochCommit, padding: nil, text: payload.text)
        return payload
    }

    private static func padPayload(_ payload: MessagePayload) throws -> (data: Data, paddingBucket: Int) {
        var padded = payload
        padded = MessagePayload(cover: payload.cover, epochCommit: payload.epochCommit, padding: "", text: payload.text)
        let target = choosePaddingBucket(try JSONEncoder.sorted.encode(padded).count)

        while try JSONEncoder.sorted.encode(padded).count < target {
            padded = MessagePayload(
                cover: payload.cover,
                epochCommit: payload.epochCommit,
                padding: (padded.padding ?? "") + ".",
                text: payload.text
            )
        }

        while let padding = padded.padding, !padding.isEmpty, try JSONEncoder.sorted.encode(padded).count > target {
            padded = MessagePayload(
                cover: payload.cover,
                epochCommit: payload.epochCommit,
                padding: String(padding.dropLast()),
                text: payload.text
            )
        }

        return (data: try JSONEncoder.sorted.encode(padded), paddingBucket: target)
    }

    private static func advanceSendRatchet(_ threadState: PairwiseThreadState) throws -> (nextState: PairwiseThreadState, ratchetPublicJwk: JWK) {
        var nextState = threadState
        let localRatchet = try generateRatchetKeyPair()
        guard let remoteRatchetPublicJwk = nextState.remoteRatchetPublicJwk else {
            throw NativeProtocolError.missingLocalRatchet
        }
        let remoteRatchetPublicKey = try publicKeyAgreementKey(from: remoteRatchetPublicJwk)
        let sharedBits = sharedSecretData(try localRatchet.privateKey.sharedSecretFromKeyAgreement(with: remoteRatchetPublicKey))
        let rootStep = deriveRootStep(rootKeyBytes: try base64Data(nextState.rootKey), dhBits: sharedBits)

        nextState.localRatchetPrivateRepresentation = localRatchet.privateRepresentation
        nextState.localRatchetPublicJwk = localRatchet.publicJwk
        nextState.pendingSendRatchet = false
        nextState.rootKey = rootStep.rootKeyBytes.base64EncodedString()
        nextState.sendChainKey = rootStep.chainKeyBytes.base64EncodedString()
        nextState.sendCounter = 0

        return (nextState: nextState, ratchetPublicJwk: localRatchet.publicJwk)
    }

    private static func ensureGroupSenderState(
        _ threadState: inout GroupTreeThreadState,
        epoch: Int,
        senderId: String
    ) throws -> GroupSenderState {
        let key = groupSenderStateKey(epoch: epoch, senderId: senderId)
        if let existing = threadState.senderStates[key] {
            return existing
        }

        guard let epochSecret = threadState.epochSecrets[String(epoch)] else {
            throw NativeProtocolError.missingEpochSecret(epoch)
        }

        let chainKeyBytes = deriveGroupSenderChain(
            epochSecretBytes: try base64Data(epochSecret),
            threadId: threadState.threadId,
            epoch: epoch,
            senderId: senderId
        )
        let state = GroupSenderState(chainKey: chainKeyBytes.base64EncodedString(), counter: 0)
        threadState.senderStates[key] = state
        return state
    }

    private static func groupSenderStateKey(epoch: Int, senderId: String) -> String {
        "\(epoch):\(senderId)"
    }

    private static func deriveMessageStep(chainKeyBytes: Data) -> (messageKeyBytes: Data, nextChainKeyBytes: Data) {
        let material = hkdfBytes(
            ikm: chainKeyBytes,
            salt: Data("notrus-chain-step".utf8),
            info: Data("notrus-chain-step-output".utf8),
            length: 64
        )

        return (
            messageKeyBytes: material.prefix(32),
            nextChainKeyBytes: material.suffix(32)
        )
    }

    private static func deriveRootStep(rootKeyBytes: Data, dhBits: Data) -> (rootKeyBytes: Data, chainKeyBytes: Data) {
        let material = hkdfBytes(
            ikm: dhBits,
            salt: rootKeyBytes,
            info: Data("notrus-pairwise-ratchet-step".utf8),
            length: 64
        )

        return (
            rootKeyBytes: material.prefix(32),
            chainKeyBytes: material.suffix(32)
        )
    }

    private static func deriveInitialRootBytes(roomKeyBytes: Data, dhBits: Data, threadId: String) -> Data {
        hkdfBytes(
            ikm: dhBits,
            salt: roomKeyBytes,
            info: Data("notrus-pairwise-root:\(threadId)".utf8),
            length: 32
        )
    }

    private static func deriveInitialCreatorChain(rootKeyBytes: Data, threadId: String, creatorId: String, recipientId: String) -> Data {
        hkdfBytes(
            ikm: rootKeyBytes,
            salt: Data(threadId.utf8),
            info: Data("notrus-initial-chain:\(creatorId)->\(recipientId)".utf8),
            length: 32
        )
    }

    private static func deriveGroupSenderChain(epochSecretBytes: Data, threadId: String, epoch: Int, senderId: String) -> Data {
        hkdfBytes(
            ikm: epochSecretBytes,
            salt: Data("\(threadId):\(epoch)".utf8),
            info: Data("notrus-group-sender-chain:\(senderId)".utf8),
            length: 32
        )
    }

    private static func computeGroupTreeHash(epoch: Int, participantIds: [String], threadId: String) -> String {
        sha256Hex(
            """
            {"epoch":\(epoch),"kind":"notrus-group-tree-state-v3","participantIds":\(jsonStringArray(participantIds)),"threadId":"\(threadId)"}
            """
        )
    }

    private static func computeGroupGenesisTranscriptHash(participantIds: [String], threadId: String, treeHash: String) -> String {
        sha256Hex(
            """
            {"kind":"notrus-group-tree-genesis-v3","participantIds":\(jsonStringArray(participantIds)),"threadId":"\(threadId)","treeHash":"\(treeHash)"}
            """
        )
    }

    private static func computeGroupTranscriptHash(
        addedIds: [String],
        commitType: String,
        committedAt: String,
        committedBy: String,
        epoch: Int,
        parentTranscriptHash: String,
        participantIds: [String],
        removedIds: [String],
        threadId: String,
        treeHash: String
    ) -> String {
        sha256Hex(
            """
            {"addedIds":\(jsonStringArray(addedIds)),"commitType":"\(commitType)","committedAt":"\(committedAt)","committedBy":"\(committedBy)","epoch":\(epoch),"kind":"notrus-group-tree-commit-v3","parentTranscriptHash":"\(parentTranscriptHash)","participantIds":\(jsonStringArray(participantIds)),"removedIds":\(jsonStringArray(removedIds)),"threadId":"\(threadId)","treeHash":"\(treeHash)"}
            """
        )
    }

    private static func hkdfBytes(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        symmetricKeyData(
            HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: ikm),
                salt: salt,
                info: info,
                outputByteCount: length
            )
        )
    }

    private static func sharedSecretData(_ sharedSecret: SharedSecret) -> Data {
        sharedSecret.withUnsafeBytes { Data($0) }
    }

    private static func symmetricKeyData(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    private static func sha256Hex(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func cacheSkippedMessageKey(
        _ threadState: inout PairwiseThreadState,
        publicJwk: JWK?,
        counter: Int,
        messageKeyBytes: Data
    ) throws {
        guard let publicJwk else {
            return
        }

        let keyId = try "\(computeFingerprint(for: publicJwk)):\(counter)"
        threadState.skippedMessageKeys[keyId] = messageKeyBytes.base64EncodedString()

        let keys = threadState.skippedMessageKeys.keys.sorted()
        if keys.count > 64, let oldest = keys.first {
            threadState.skippedMessageKeys.removeValue(forKey: oldest)
        }
    }

    private static func takeSkippedMessageKey(
        _ threadState: inout PairwiseThreadState,
        publicJwk: JWK?,
        counter: Int
    ) throws -> Data? {
        guard let publicJwk else {
            return nil
        }

        let keyId = try "\(computeFingerprint(for: publicJwk)):\(counter)"
        guard let encoded = threadState.skippedMessageKeys.removeValue(forKey: keyId) else {
            return nil
        }
        return try base64Data(encoded)
    }

    private static func canonicalizeEnvelope(_ envelope: RelayEnvelope) -> String {
        """
        {"ciphertext":"\(envelope.ciphertext)","createdAt":"\(envelope.createdAt)","fromUserId":"\(envelope.fromUserId)","iv":"\(envelope.iv)","signature":"\(envelope.signature)","threadId":"\(envelope.threadId)","toUserId":"\(envelope.toUserId)"}
        """
    }

    private static func canonicalizeGroupCommit(_ groupCommit: RelayGroupCommit?) -> String? {
        guard let groupCommit else {
            return nil
        }

        let envelopes = groupCommit.envelopes
            .sorted { $0.toUserId < $1.toUserId }
            .map(canonicalizeEnvelope)
            .joined(separator: ",")

        return """
        {"addedIds":\(jsonStringArray(groupCommit.addedIds)),"commitType":\(jsonNullableString(groupCommit.commitType)),"committedAt":\(jsonNullableString(groupCommit.committedAt)),"committedBy":\(jsonNullableString(groupCommit.committedBy)),"envelopes":[\(envelopes)],"epoch":\(groupCommit.epoch),"parentTranscriptHash":"\(groupCommit.parentTranscriptHash)","participantIds":\(jsonStringArray(groupCommit.participantIds)),"removedIds":\(jsonStringArray(groupCommit.removedIds)),"transcriptHash":"\(groupCommit.transcriptHash)","treeHash":"\(groupCommit.treeHash)"}
        """
    }

    static func messageAad(
        threadId: String,
        id: String,
        senderId: String,
        createdAt: String,
        protocolName: String,
        counter: Int?,
        epoch: Int?,
        groupCommit: RelayGroupCommit?,
        ratchetPublicJwk: JWK?,
        paddingBucket: Int?
    ) -> String {
        """
        {"counter":\(jsonNullableInt(counter)),"createdAt":"\(createdAt)","epoch":\(jsonNullableInt(epoch)),"groupCommit":\(jsonNullableString(canonicalizeGroupCommit(groupCommit))),"id":"\(id)","kind":"notrus-message","paddingBucket":\(jsonNullableInt(paddingBucket)),"protocol":"\(protocolName)","ratchetKey":\(jsonNullableString(ratchetPublicJwk.map(canonicalEcFingerprintSource))),"senderId":"\(senderId)","threadId":"\(threadId)"}
        """
    }

    static func messageSignaturePayload(
        id: String,
        threadId: String,
        senderId: String,
        createdAt: String,
        iv: String,
        ciphertext: String,
        protocolName: String,
        counter: Int?,
        epoch: Int?,
        groupCommit: RelayGroupCommit?,
        ratchetPublicJwk: JWK?,
        paddingBucket: Int?
    ) -> String {
        """
        {"ciphertext":"\(ciphertext)","counter":\(jsonNullableInt(counter)),"createdAt":"\(createdAt)","epoch":\(jsonNullableInt(epoch)),"groupCommit":\(jsonNullableString(canonicalizeGroupCommit(groupCommit))),"id":"\(id)","iv":"\(iv)","kind":"notrus-message-signature","paddingBucket":\(jsonNullableInt(paddingBucket)),"protocol":"\(protocolName)","ratchetKey":\(jsonNullableString(ratchetPublicJwk.map(canonicalEcFingerprintSource))),"senderId":"\(senderId)","threadId":"\(threadId)"}
        """
    }

    private static func jsonNullableString(_ value: String?) -> String {
        value.map(jsonString) ?? "null"
    }

    private static func jsonStringArray(_ values: [String]) -> String {
        "[\(values.map(jsonString).joined(separator: ","))]"
    }
}

private extension JSONEncoder {
    static var sorted: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}
