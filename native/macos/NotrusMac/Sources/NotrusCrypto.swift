import CryptoKit
import Foundation

enum NotrusCryptoError: LocalizedError {
    case archiveDecryptionFailed
    case invalidBase64
    case invalidJWK
    case invalidEnvelopeSignature
    case invalidMessageSignature
    case malformedCiphertext
    case unsupportedPayload

    var errorDescription: String? {
        switch self {
        case .archiveDecryptionFailed:
            return "The recovery archive could not be opened. Check the passphrase and try again."
        case .invalidBase64:
            return "The encoded crypto payload was not valid base64."
        case .invalidJWK:
            return "The public key payload was not a valid P-256 JWK."
        case .invalidEnvelopeSignature:
            return "Envelope signature verification failed."
        case .invalidMessageSignature:
            return "Message signature verification failed."
        case .malformedCiphertext:
            return "The ciphertext payload was malformed."
        case .unsupportedPayload:
            return "The message payload could not be decoded by the native client."
        }
    }
}

enum SigningPrivateKeyHandle {
    case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)
    case software(P256.Signing.PrivateKey)

    var publicKey: P256.Signing.PublicKey {
        switch self {
        case .secureEnclave(let key):
            return key.publicKey
        case .software(let key):
            return key.publicKey
        }
    }

    func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
        switch self {
        case .secureEnclave(let key):
            return try key.signature(for: data)
        case .software(let key):
            return try key.signature(for: data)
        }
    }
}

enum KeyAgreementPrivateKeyHandle {
    case secureEnclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
    case software(P256.KeyAgreement.PrivateKey)

    var publicKey: P256.KeyAgreement.PublicKey {
        switch self {
        case .secureEnclave(let key):
            return key.publicKey
        case .software(let key):
            return key.publicKey
        }
    }

    func sharedSecret(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        switch self {
        case .secureEnclave(let key):
            return try key.sharedSecretFromKeyAgreement(with: publicKey)
        case .software(let key):
            return try key.sharedSecretFromKeyAgreement(with: publicKey)
        }
    }
}

enum NotrusCrypto {
    static let messagePadBuckets = [256, 512, 1024, 2048, 4096]

    static func createSignedPrekey(signingKey: SigningPrivateKeyHandle, userId: String) throws -> (
        createdAt: String,
        fingerprint: String,
        publicJwk: JWK,
        representation: String,
        signature: String
    ) {
        let prekeyPrivateKey = P256.KeyAgreement.PrivateKey()
        let prekeyPublicJwk = try jwk(from: prekeyPrivateKey.publicKey.x963Representation)
        let createdAt = isoNow()
        let signature = try signText(
            signingKey,
            text: signedPrekeyPayload(createdAt: createdAt, prekeyPublicJwk: prekeyPublicJwk, userId: userId)
        )

        return (
            createdAt: createdAt,
            fingerprint: try computeFingerprint(for: prekeyPublicJwk),
            publicJwk: prekeyPublicJwk,
            representation: prekeyPrivateKey.rawRepresentation.base64EncodedString(),
            signature: signature
        )
    }

    static func createIdentity(displayName: String, username: String) throws -> LocalIdentity {
        let userId = UUID().uuidString.lowercased()
        let recoveryPrivateKey = P256.Signing.PrivateKey()
        let recoveryPublicJwk = try jwk(from: recoveryPrivateKey.publicKey.x963Representation)
        let signingPrivateKey = P256.Signing.PrivateKey()
        let encryptionPrivateKey = P256.KeyAgreement.PrivateKey()
        let signingPublicJwk = try jwk(from: signingPrivateKey.publicKey.x963Representation)
        let encryptionPublicJwk = try jwk(from: encryptionPrivateKey.publicKey.x963Representation)
        let prekey = try createSignedPrekey(signingKey: .software(signingPrivateKey), userId: userId)

        return LocalIdentity(
            id: userId,
            username: username,
            displayName: displayName,
            createdAt: isoNow(),
            storageMode: "device-vault-v2",
            fingerprint: try computeIdentityFingerprint(
                encryptionPublicJwk: encryptionPublicJwk,
                signingPublicJwk: signingPublicJwk
            ),
            recoveryFingerprint: try computeFingerprint(for: recoveryPublicJwk),
            recoveryPublicJwk: recoveryPublicJwk,
            recoveryRepresentation: recoveryPrivateKey.rawRepresentation.base64EncodedString(),
            signingPublicJwk: signingPublicJwk,
            signingRepresentation: signingPrivateKey.rawRepresentation.base64EncodedString(),
            encryptionPublicJwk: encryptionPublicJwk,
            encryptionRepresentation: encryptionPrivateKey.rawRepresentation.base64EncodedString(),
            prekeyCreatedAt: prekey.createdAt,
            prekeyFingerprint: prekey.fingerprint,
            prekeyPublicJwk: prekey.publicJwk,
            prekeyRepresentation: prekey.representation,
            prekeySignature: prekey.signature,
            standardsMlsKeyPackage: nil,
            standardsMlsState: nil,
            standardsSignalBundle: nil,
            standardsSignalState: nil
        )
    }

    static func restoreIdentity(_ identity: LocalIdentity) throws -> LocalIdentity {
        let recoveryPrivateKey = try loadSigningPrivateKey(identity.recoveryRepresentation)
        let signingPrivateKey = try loadSigningPrivateKey(identity.signingRepresentation)
        let encryptionPrivateKey = try loadKeyAgreementPrivateKey(identity.encryptionRepresentation)
        let recoveryPublicJwk = try jwk(from: recoveryPrivateKey.publicKey.x963Representation)
        let signingPublicJwk = try jwk(from: signingPrivateKey.publicKey.x963Representation)
        let encryptionPublicJwk = try jwk(from: encryptionPrivateKey.publicKey.x963Representation)
        let restoredPrekey = try restoredSignedPrekey(
            identity: identity,
            signingPrivateKey: signingPrivateKey
        )

        return LocalIdentity(
            id: identity.id,
            username: identity.username,
            displayName: identity.displayName,
            createdAt: identity.createdAt,
            storageMode: identity.storageMode ?? inferredStorageMode(
                recoveryKey: recoveryPrivateKey,
                signingKey: signingPrivateKey,
                encryptionKey: encryptionPrivateKey,
                prekeyKey: restoredPrekey.privateKey
            ),
            fingerprint: try computeIdentityFingerprint(
                encryptionPublicJwk: encryptionPublicJwk,
                signingPublicJwk: signingPublicJwk
            ),
            recoveryFingerprint: try computeFingerprint(for: recoveryPublicJwk),
            recoveryPublicJwk: recoveryPublicJwk,
            recoveryRepresentation: identity.recoveryRepresentation,
            signingPublicJwk: signingPublicJwk,
            signingRepresentation: identity.signingRepresentation,
            encryptionPublicJwk: encryptionPublicJwk,
            encryptionRepresentation: identity.encryptionRepresentation,
            prekeyCreatedAt: restoredPrekey.createdAt,
            prekeyFingerprint: restoredPrekey.fingerprint,
            prekeyPublicJwk: restoredPrekey.publicJwk,
            prekeyRepresentation: restoredPrekey.representation,
            prekeySignature: restoredPrekey.signature,
            standardsMlsKeyPackage: identity.standardsMlsKeyPackage,
            standardsMlsState: identity.standardsMlsState,
            standardsSignalBundle: identity.standardsSignalBundle,
            standardsSignalState: identity.standardsSignalState
        )
    }

    static func rotatedIdentity(from identity: LocalIdentity) throws -> LocalIdentity {
        let signingPrivateKey = P256.Signing.PrivateKey()
        let encryptionPrivateKey = P256.KeyAgreement.PrivateKey()
        let signingPublicJwk = try jwk(from: signingPrivateKey.publicKey.x963Representation)
        let encryptionPublicJwk = try jwk(from: encryptionPrivateKey.publicKey.x963Representation)
        let prekey = try createSignedPrekey(signingKey: .software(signingPrivateKey), userId: identity.id)

        return LocalIdentity(
            id: identity.id,
            username: identity.username,
            displayName: identity.displayName,
            createdAt: identity.createdAt,
            storageMode: "device-vault-v2",
            fingerprint: try computeIdentityFingerprint(
                encryptionPublicJwk: encryptionPublicJwk,
                signingPublicJwk: signingPublicJwk
            ),
            recoveryFingerprint: identity.recoveryFingerprint,
            recoveryPublicJwk: identity.recoveryPublicJwk,
            recoveryRepresentation: identity.recoveryRepresentation,
            signingPublicJwk: signingPublicJwk,
            signingRepresentation: signingPrivateKey.rawRepresentation.base64EncodedString(),
            encryptionPublicJwk: encryptionPublicJwk,
            encryptionRepresentation: encryptionPrivateKey.rawRepresentation.base64EncodedString(),
            prekeyCreatedAt: prekey.createdAt,
            prekeyFingerprint: prekey.fingerprint,
            prekeyPublicJwk: prekey.publicJwk,
            prekeyRepresentation: prekey.representation,
            prekeySignature: prekey.signature,
            standardsMlsKeyPackage: nil,
            standardsMlsState: nil,
            standardsSignalBundle: nil,
            standardsSignalState: nil
        )
    }

    static func wrapRoomKeyForRecipient(
        createdAt: String,
        fromUserId: String,
        recipientEncryptionPublicJwk: JWK,
        roomKey: Data,
        senderEncryptionRepresentation: String,
        senderSigningRepresentation: String,
        threadId: String,
        toUserId: String
    ) throws -> RelayEnvelope {
        let senderEncryptionPrivateKey = try loadKeyAgreementPrivateKey(senderEncryptionRepresentation)
        let senderSigningPrivateKey = try loadSigningPrivateKey(senderSigningRepresentation)
        let recipientPublicKey = try publicKeyAgreementKey(from: recipientEncryptionPublicJwk)
        let wrappingKey = try deriveWrappingKey(
            privateKey: senderEncryptionPrivateKey,
            publicKey: recipientPublicKey,
            threadId: threadId,
            leftUserId: fromUserId,
            rightUserId: toUserId
        )

        let iv = randomData(count: 12)
        let aad = Data(envelopeAad(threadId: threadId, fromUserId: fromUserId, toUserId: toUserId, createdAt: createdAt).utf8)
        let sealed = try AES.GCM.seal(roomKey, using: wrappingKey, nonce: .init(data: iv), authenticating: aad)
        let ciphertext = sealed.ciphertext + sealed.tag
        let unsignedEnvelope = RelayEnvelope(
            threadId: threadId,
            fromUserId: fromUserId,
            toUserId: toUserId,
            createdAt: createdAt,
            iv: iv.base64EncodedString(),
            ciphertext: ciphertext.base64EncodedString(),
            signature: ""
        )

        return RelayEnvelope(
            threadId: threadId,
            fromUserId: fromUserId,
            toUserId: toUserId,
            createdAt: createdAt,
            iv: unsignedEnvelope.iv,
            ciphertext: unsignedEnvelope.ciphertext,
            signature: try signText(senderSigningPrivateKey, text: envelopeSignaturePayload(unsignedEnvelope))
        )
    }

    static func unwrapRoomKeyEnvelope(
        envelope: RelayEnvelope,
        recipientEncryptionRepresentation: String,
        senderEncryptionPublicJwk: JWK,
        senderSigningPublicJwk: JWK
    ) throws -> Data {
        let signingPublicKey = try publicSigningKey(from: senderSigningPublicJwk)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: try base64Data(envelope.signature))
        guard signingPublicKey.isValidSignature(signature, for: Data(envelopeSignaturePayload(envelope).utf8)) else {
            throw NotrusCryptoError.invalidEnvelopeSignature
        }

        let recipientPrivateKey = try loadKeyAgreementPrivateKey(recipientEncryptionRepresentation)
        let senderEncryptionKey = try publicKeyAgreementKey(from: senderEncryptionPublicJwk)
        let wrappingKey = try deriveWrappingKey(
            privateKey: recipientPrivateKey,
            publicKey: senderEncryptionKey,
            threadId: envelope.threadId,
            leftUserId: envelope.fromUserId,
            rightUserId: envelope.toUserId
        )

        let ciphertextWithTag = try base64Data(envelope.ciphertext)
        guard ciphertextWithTag.count >= 16 else {
            throw NotrusCryptoError.malformedCiphertext
        }

        let sealedBox = try AES.GCM.SealedBox(
            nonce: .init(data: try base64Data(envelope.iv)),
            ciphertext: ciphertextWithTag.prefix(ciphertextWithTag.count - 16),
            tag: ciphertextWithTag.suffix(16)
        )

        return try AES.GCM.open(
            sealedBox,
            using: wrappingKey,
            authenticating: Data(
                envelopeAad(
                    threadId: envelope.threadId,
                    fromUserId: envelope.fromUserId,
                    toUserId: envelope.toUserId,
                    createdAt: envelope.createdAt
                ).utf8
            )
        )
    }

    static func sealMessage(
        text: String,
        roomKey: Data,
        senderId: String,
        senderSigningRepresentation: String,
        threadId: String
    ) throws -> OutboundMessage {
        let createdAt = isoNow()
        let id = UUID().uuidString.lowercased()
        let iv = randomData(count: 12)
        let padded = padTextPayload(text: text)
        let symmetricKey = SymmetricKey(data: roomKey)
        let aad = Data(
            messageAad(
                threadId: threadId,
                id: id,
                senderId: senderId,
                createdAt: createdAt,
                protocolName: "static-room-v1",
                counter: nil,
                epoch: nil,
                groupCommit: nil,
                ratchetPublicJwk: nil,
                paddingBucket: padded.paddingBucket
            ).utf8
        )
        let sealed = try AES.GCM.seal(Data(padded.serialized.utf8), using: symmetricKey, nonce: .init(data: iv), authenticating: aad)
        let ciphertext = sealed.ciphertext + sealed.tag
        let signingKey = try loadSigningPrivateKey(senderSigningRepresentation)
        let signaturePayload = messageSignaturePayload(
            id: id,
            threadId: threadId,
            senderId: senderId,
            createdAt: createdAt,
            iv: iv.base64EncodedString(),
            ciphertext: ciphertext.base64EncodedString(),
            protocolName: "static-room-v1",
            counter: nil,
            epoch: nil,
            groupCommit: nil,
            ratchetPublicJwk: nil,
            paddingBucket: padded.paddingBucket
        )

        return OutboundMessage(
            ciphertext: ciphertext.base64EncodedString(),
            counter: nil,
            createdAt: createdAt,
            epoch: nil,
            groupCommit: nil,
            id: id,
            iv: iv.base64EncodedString(),
            messageKind: nil,
            paddingBucket: padded.paddingBucket,
            protocolField: "static-room-v1",
            ratchetPublicJwk: nil,
            senderId: senderId,
            signature: try signText(signingKey, text: signaturePayload),
            threadId: threadId,
            wireMessage: nil
        )
    }

    static func openMessage(
        message: RelayMessage,
        roomKey: Data,
        senderSigningPublicJwk: JWK
    ) throws -> String {
        guard
            let signaturePayload = message.signature,
            let ivPayload = message.iv,
            let ciphertextPayload = message.ciphertext
        else {
            throw NotrusCryptoError.malformedCiphertext
        }
        let signingPublicKey = try publicSigningKey(from: senderSigningPublicJwk)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: try base64Data(signaturePayload))
        let signedMessagePayload = messageSignaturePayload(
            id: message.id,
            threadId: message.threadId ?? "",
            senderId: message.senderId,
            createdAt: message.createdAt,
            iv: ivPayload,
            ciphertext: ciphertextPayload,
            protocolName: message.protocolField ?? "static-room-v1",
            counter: message.counter,
            epoch: message.epoch,
            groupCommit: nil,
            ratchetPublicJwk: nil,
            paddingBucket: message.paddingBucket
        )
        guard signingPublicKey.isValidSignature(signature, for: Data(signedMessagePayload.utf8)) else {
            throw NotrusCryptoError.invalidMessageSignature
        }

        let ciphertextWithTag = try base64Data(ciphertextPayload)
        guard ciphertextWithTag.count >= 16 else {
            throw NotrusCryptoError.malformedCiphertext
        }

        let aad = Data(
            messageAad(
                threadId: message.threadId ?? "",
                id: message.id,
                senderId: message.senderId,
                createdAt: message.createdAt,
                protocolName: message.protocolField ?? "static-room-v1",
                counter: message.counter,
                epoch: message.epoch,
                groupCommit: nil,
                ratchetPublicJwk: nil,
                paddingBucket: message.paddingBucket
            ).utf8
        )
        let sealedBox = try AES.GCM.SealedBox(
            nonce: .init(data: try base64Data(ivPayload)),
            ciphertext: ciphertextWithTag.prefix(ciphertextWithTag.count - 16),
            tag: ciphertextWithTag.suffix(16)
        )
        let plaintext = try AES.GCM.open(sealedBox, using: SymmetricKey(data: roomKey), authenticating: aad)
        return try unpadTextPayload(data: plaintext)
    }

    static func randomRoomKey() -> Data {
        randomData(count: 32)
    }

    static func sealAttachment(
        data: Data,
        fileName: String = "attachment.bin",
        mediaType: String = "application/octet-stream",
        senderId: String,
        threadId: String
    ) throws -> (request: AttachmentUploadRequest, reference: SecureAttachmentReference) {
        let attachmentKey = randomData(count: 32)
        let attachmentId = UUID().uuidString.lowercased()
        let createdAt = isoNow()
        let iv = randomData(count: 12)
        let aad = Data(
            """
            {"attachmentId":"\(attachmentId)","createdAt":"\(createdAt)","kind":"notrus-attachment","senderId":"\(senderId)","threadId":"\(threadId)"}
            """.utf8
        )
        let sealed = try AES.GCM.seal(
            data,
            using: SymmetricKey(data: attachmentKey),
            nonce: .init(data: iv),
            authenticating: aad
        )
        guard let combined = sealed.combined else {
            throw NotrusCryptoError.malformedCiphertext
        }
        let ciphertext = combined.dropFirst(12)
        let sha256 = SHA256.hash(data: combined).map { String(format: "%02x", $0) }.joined()

        return (
            request: AttachmentUploadRequest(
                byteLength: data.count,
                ciphertext: ciphertext.base64EncodedString(),
                createdAt: createdAt,
                id: attachmentId,
                iv: combined.prefix(12).base64EncodedString(),
                senderId: senderId,
                sha256: sha256,
                threadId: threadId
            ),
            reference: SecureAttachmentReference(
                id: attachmentId,
                attachmentKey: attachmentKey.base64EncodedString(),
                byteLength: data.count,
                mediaType: mediaType,
                fileName: fileName,
                sha256: sha256
            )
        )
    }

    static func openAttachment(_ attachment: RelayAttachment, reference: SecureAttachmentReference) throws -> Data {
        let combined = try base64Data(attachment.iv) + base64Data(attachment.ciphertext)
        let digest = SHA256.hash(data: combined).map { String(format: "%02x", $0) }.joined()
        guard digest == reference.sha256 else {
            throw NotrusCryptoError.invalidEnvelopeSignature
        }

        let sealedBox = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(
            sealedBox,
            using: SymmetricKey(data: try base64Data(reference.attachmentKey)),
            authenticating: Data(
                """
                {"attachmentId":"\(attachment.id)","createdAt":"\(attachment.createdAt)","kind":"notrus-attachment","senderId":"\(attachment.senderId)","threadId":"\(attachment.threadId)"}
                """.utf8
            )
        )
    }

    static func jwk(from x963: Data) throws -> JWK {
        guard x963.count == 65, x963.first == 0x04 else {
            throw NotrusCryptoError.invalidJWK
        }

        return JWK(
            crv: "P-256",
            kty: "EC",
            x: base64url(x963[1...32]),
            y: base64url(x963[33...64])
        )
    }

    static func publicSigningKey(from jwk: JWK) throws -> P256.Signing.PublicKey {
        try P256.Signing.PublicKey(x963Representation: try x963Data(from: jwk))
    }

    static func publicKeyAgreementKey(from jwk: JWK) throws -> P256.KeyAgreement.PublicKey {
        try P256.KeyAgreement.PublicKey(x963Representation: try x963Data(from: jwk))
    }

    static func loadSigningPrivateKey(_ representation: String) throws -> SigningPrivateKeyHandle {
        let data = try base64Data(representation)
        if let secureEnclaveKey = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data) {
            return .secureEnclave(secureEnclaveKey)
        }
        return .software(try P256.Signing.PrivateKey(rawRepresentation: data))
    }

    static func loadKeyAgreementPrivateKey(_ representation: String) throws -> KeyAgreementPrivateKeyHandle {
        let data = try base64Data(representation)
        if let secureEnclaveKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data) {
            return .secureEnclave(secureEnclaveKey)
        }
        return .software(try P256.KeyAgreement.PrivateKey(rawRepresentation: data))
    }

    static func computeIdentityFingerprint(encryptionPublicJwk: JWK, signingPublicJwk: JWK) throws -> String {
        let source = """
        {"encryption":\(canonicalEcFingerprintSource(encryptionPublicJwk)),"signing":\(canonicalEcFingerprintSource(signingPublicJwk))}
        """
        return try formatFingerprint(hex: SHA256.hash(data: Data(source.utf8)).map { String(format: "%02x", $0) }.joined())
    }

    static func computeFingerprint(for jwk: JWK) throws -> String {
        let source = canonicalEcFingerprintSource(jwk)
        return try formatFingerprint(hex: SHA256.hash(data: Data(source.utf8)).map { String(format: "%02x", $0) }.joined())
    }

    static func signedPrekeyPayload(createdAt: String, prekeyPublicJwk: JWK, userId: String) -> String {
        """
        {"createdAt":"\(createdAt)","kind":"notrus-signed-prekey","prekey":\(jsonString(canonicalEcFingerprintSource(prekeyPublicJwk))),"userId":"\(userId)"}
        """
    }

    static func accountResetSignaturePayload(_ request: AccountResetRequest) -> String {
        """
        {"createdAt":\(jsonString(request.createdAt)),"displayName":\(jsonString(request.displayName)),"encryption":\(canonicalEcFingerprintSource(request.encryptionPublicJwk)),"fingerprint":\(jsonString(request.fingerprint)),"mlsKeyPackage":\(request.mlsKeyPackage.map { jsonString($0.keyPackage) } ?? "null"),"prekeyCreatedAt":\(jsonString(request.prekeyCreatedAt)),"prekeyFingerprint":\(jsonString(request.prekeyFingerprint)),"prekeyPublicJwk":\(canonicalEcFingerprintSource(request.prekeyPublicJwk)),"prekeySignature":\(jsonString(request.prekeySignature)),"recoveryFingerprint":\(jsonString(request.recoveryFingerprint)),"recoveryPublicJwk":\(canonicalEcFingerprintSource(request.recoveryPublicJwk)),"signalBundle":\(request.signalBundle.map(signalBundleCanonicalSource) ?? "null"),"signing":\(canonicalEcFingerprintSource(request.signingPublicJwk)),"userId":\(jsonString(request.userId)),"username":\(jsonString(request.username))}
        """
    }

    static func deviceActionSignaturePayload(
        action: String,
        createdAt: String,
        signerDeviceId: String,
        targetDeviceId: String,
        userId: String
    ) -> String {
        """
        {"action":\(jsonString(action)),"createdAt":\(jsonString(createdAt)),"signerDeviceId":\(jsonString(signerDeviceId)),"targetDeviceId":\(jsonString(targetDeviceId)),"userId":\(jsonString(userId))}
        """
    }

    static func signAccountReset(_ request: AccountResetRequest, recoveryRepresentation: String) throws -> String {
        let recoveryKey = try loadSigningPrivateKey(recoveryRepresentation)
        return try signText(recoveryKey, text: accountResetSignaturePayload(request))
    }

    static func envelopeAad(threadId: String, fromUserId: String, toUserId: String, createdAt: String) -> String {
        """
        {"createdAt":"\(createdAt)","fromUserId":"\(fromUserId)","kind":"notrus-room-envelope","threadId":"\(threadId)","toUserId":"\(toUserId)"}
        """
    }

    static func envelopeSignaturePayload(_ envelope: RelayEnvelope) -> String {
        """
        {"ciphertext":"\(envelope.ciphertext)","createdAt":"\(envelope.createdAt)","fromUserId":"\(envelope.fromUserId)","iv":"\(envelope.iv)","kind":"notrus-room-envelope-signature","threadId":"\(envelope.threadId)","toUserId":"\(envelope.toUserId)"}
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
        paddingBucket: Int?
    ) -> String {
        """
        {"counter":\(jsonNullableInt(counter)),"createdAt":"\(createdAt)","epoch":\(jsonNullableInt(epoch)),"groupCommit":null,"id":"\(id)","kind":"notrus-message","paddingBucket":\(jsonNullableInt(paddingBucket)),"protocol":"\(protocolName)","ratchetKey":null,"senderId":"\(senderId)","threadId":"\(threadId)"}
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
        paddingBucket: Int?
    ) -> String {
        """
        {"ciphertext":"\(ciphertext)","counter":\(jsonNullableInt(counter)),"createdAt":"\(createdAt)","epoch":\(jsonNullableInt(epoch)),"groupCommit":null,"id":"\(id)","iv":"\(iv)","kind":"notrus-message-signature","paddingBucket":\(jsonNullableInt(paddingBucket)),"protocol":"\(protocolName)","ratchetKey":null,"senderId":"\(senderId)","threadId":"\(threadId)"}
        """
    }

    static func deriveWrappingKey(
        privateKey: KeyAgreementPrivateKeyHandle,
        publicKey: P256.KeyAgreement.PublicKey,
        threadId: String,
        leftUserId: String,
        rightUserId: String
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecret(with: publicKey)
        let sortedPair = [leftUserId, rightUserId].sorted().joined(separator: ":")
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("notrus-room-wrap:\(threadId):\(sortedPair)".utf8),
            sharedInfo: Data("notrus-room-wrap-v1".utf8),
            outputByteCount: 32
        )
    }

    static func signText(_ key: SigningPrivateKeyHandle, text: String) throws -> String {
        try key.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString()
    }

    static func x963Data(from jwk: JWK) throws -> Data {
        guard let x = Data(base64URLEncoded: jwk.x), let y = Data(base64URLEncoded: jwk.y) else {
            throw NotrusCryptoError.invalidJWK
        }

        return Data([0x04]) + x + y
    }

    static func base64Data(_ value: String) throws -> Data {
        guard let data = Data(base64Encoded: value) else {
            throw NotrusCryptoError.invalidBase64
        }

        return data
    }

    static func base64url<T: DataProtocol>(_ value: T) -> String {
        Data(value)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func canonicalEcFingerprintSource(_ jwk: JWK) -> String {
        """
        {"crv":"\(jwk.crv)","kty":"\(jwk.kty)","x":"\(jwk.x)","y":"\(jwk.y)"}
        """
    }

    static func isoNow() -> String {
        ISO8601DateFormatter().string(from: Date())
    }

    static func randomData(count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
    }

    static func formatFingerprint(hex: String) throws -> String {
        guard !hex.isEmpty else {
            throw NotrusCryptoError.invalidJWK
        }

        return stride(from: 0, to: hex.count, by: 4).map { index in
            let start = hex.index(hex.startIndex, offsetBy: index)
            let end = hex.index(start, offsetBy: min(4, hex.distance(from: start, to: hex.endIndex)), limitedBy: hex.endIndex) ?? hex.endIndex
            return String(hex[start..<end])
        }.joined(separator: " ")
    }

    static func jsonString(_ value: String) -> String {
        let data = (try? JSONSerialization.data(withJSONObject: [value])) ?? Data("[\"\"]".utf8)
        let rendered = String(data: data, encoding: .utf8) ?? "[\"\"]"
        return String(rendered.dropFirst().dropLast())
    }

    static func jsonNullableInt(_ value: Int?) -> String {
        value.map(String.init) ?? "null"
    }

    static func choosePaddingBucket(_ byteLength: Int) -> Int {
        for bucket in messagePadBuckets where byteLength <= bucket {
            return bucket
        }

        return Int(ceil(Double(byteLength) / 2048.0) * 2048.0)
    }

    static func textPayloadString(text: String, padding: String) -> String {
        """
        {"text":\(jsonString(text)),"padding":\(jsonString(padding))}
        """
    }

    static func padTextPayload(text: String) -> (serialized: String, paddingBucket: Int) {
        var padding = ""
        let target = choosePaddingBucket(textPayloadString(text: text, padding: padding).utf8.count)

        while textPayloadString(text: text, padding: padding).utf8.count < target {
            padding.append(".")
        }

        while !padding.isEmpty && textPayloadString(text: text, padding: padding).utf8.count > target {
            padding.removeLast()
        }

        return (serialized: textPayloadString(text: text, padding: padding), paddingBucket: target)
    }

    static func unpadTextPayload(data: Data) throws -> String {
        guard
            let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let text = object["text"] as? String
        else {
            throw NotrusCryptoError.unsupportedPayload
        }

        return text
    }

    static func deriveArchiveKey(passphrase: String, salt: Data, rounds: Int) -> SymmetricKey {
        var state = Data(passphrase.precomposedStringWithCanonicalMapping.utf8) + salt
        for round in 0..<max(1, rounds) {
            state = Data(SHA256.hash(data: state + salt + Data(String(round).utf8)))
        }
        return SymmetricKey(data: Data(SHA256.hash(data: state + salt)))
    }

    static func sealPortableArchive(_ archive: PortableAccountArchive, passphrase: String) throws -> EncryptedPortableAccountArchive {
        let salt = randomData(count: 16)
        let rounds = 120_000
        let key = deriveArchiveKey(passphrase: passphrase, salt: salt, rounds: rounds)
        let plaintext = try JSONEncoder().encode(archive)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: AES.GCM.Nonce(data: randomData(count: 12)),
            authenticating: Data("notrus-native-account-archive-v1".utf8)
        )

        guard let combined = sealed.combined else {
            throw NotrusCryptoError.archiveDecryptionFailed
        }

        return EncryptedPortableAccountArchive(
            version: 1,
            exportedAt: archive.exportedAt,
            iv: combined.prefix(12).base64EncodedString(),
            salt: salt.base64EncodedString(),
            rounds: rounds,
            ciphertext: combined.dropFirst(12).base64EncodedString()
        )
    }

    static func openPortableArchive(_ archive: EncryptedPortableAccountArchive, passphrase: String) throws -> PortableAccountArchive {
        let salt = try base64Data(archive.salt)
        let combined = try base64Data(archive.iv) + base64Data(archive.ciphertext)
        let key = deriveArchiveKey(passphrase: passphrase, salt: salt, rounds: archive.rounds)
        let sealedBox = try AES.GCM.SealedBox(combined: combined)

        do {
            let plaintext = try AES.GCM.open(
                sealedBox,
                using: key,
                authenticating: Data("notrus-native-account-archive-v1".utf8)
            )
            return try JSONDecoder().decode(PortableAccountArchive.self, from: plaintext)
        } catch {
            throw NotrusCryptoError.archiveDecryptionFailed
        }
    }

    static func inferredStorageMode(
        recoveryKey: SigningPrivateKeyHandle,
        signingKey: SigningPrivateKeyHandle,
        encryptionKey: KeyAgreementPrivateKeyHandle,
        prekeyKey: KeyAgreementPrivateKeyHandle
    ) -> String {
        let recoveryIsSecure = {
            if case .secureEnclave = recoveryKey {
                return true
            }
            return false
        }()
        let signingIsSecure = {
            if case .secureEnclave = signingKey {
                return true
            }
            return false
        }()
        let encryptionIsSecure = {
            if case .secureEnclave = encryptionKey {
                return true
            }
            return false
        }()
        let prekeyIsSecure = {
            if case .secureEnclave = prekeyKey {
                return true
            }
            return false
        }()

        return (recoveryIsSecure || signingIsSecure || encryptionIsSecure || prekeyIsSecure) ? "secure-enclave-v1" : "device-vault-v2"
    }

    private static func restoredSignedPrekey(
        identity: LocalIdentity,
        signingPrivateKey: SigningPrivateKeyHandle
    ) throws -> (
        createdAt: String,
        fingerprint: String,
        publicJwk: JWK,
        privateKey: KeyAgreementPrivateKeyHandle,
        representation: String,
        signature: String
    ) {
        if
            !identity.prekeyRepresentation.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
            let existingPrekey = try? loadKeyAgreementPrivateKey(identity.prekeyRepresentation)
        {
            let publicJwk = try jwk(from: existingPrekey.publicKey.x963Representation)
            return (
                createdAt: identity.prekeyCreatedAt,
                fingerprint: try computeFingerprint(for: publicJwk),
                publicJwk: publicJwk,
                privateKey: existingPrekey,
                representation: identity.prekeyRepresentation,
                signature: try signText(
                    signingPrivateKey,
                    text: signedPrekeyPayload(
                        createdAt: identity.prekeyCreatedAt,
                        prekeyPublicJwk: publicJwk,
                        userId: identity.id
                    )
                )
            )
        }

        let regenerated = try createSignedPrekey(
            signingKey: signingPrivateKey,
            userId: identity.id
        )
        let regeneratedPrivateKey = try loadKeyAgreementPrivateKey(regenerated.representation)
        return (
            createdAt: regenerated.createdAt,
            fingerprint: regenerated.fingerprint,
            publicJwk: regenerated.publicJwk,
            privateKey: regeneratedPrivateKey,
            representation: regenerated.representation,
            signature: regenerated.signature
        )
    }

    static func signalBundleCanonicalSource(_ bundle: PublicSignalBundle) -> String {
        """
        {"deviceId":\(bundle.deviceId),"identityKey":"\(bundle.identityKey)","kyberPreKeyId":\(bundle.kyberPreKeyId),"kyberPreKeyPublic":"\(bundle.kyberPreKeyPublic)","kyberPreKeySignature":"\(bundle.kyberPreKeySignature)","preKeyId":\(bundle.preKeyId),"preKeyPublic":"\(bundle.preKeyPublic)","registrationId":\(bundle.registrationId),"signedPreKeyId":\(bundle.signedPreKeyId),"signedPreKeyPublic":"\(bundle.signedPreKeyPublic)","signedPreKeySignature":"\(bundle.signedPreKeySignature)"}
        """
    }
}

extension Data {
    init?(base64URLEncoded value: String) {
        var padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while padded.count % 4 != 0 {
            padded.append("=")
        }

        self.init(base64Encoded: padded)
    }
}
