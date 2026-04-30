import AppKit
import Foundation

enum AccountPortabilityError: LocalizedError, Equatable {
    case exportUnsupported
    case exportCancelled
    case importCancelled
    case unsupportedArchiveFormat
    case chatBackupUsedForRecovery

    var errorDescription: String? {
        switch self {
        case .exportUnsupported:
            return "This profile was created with the older hardware-pinned format and cannot be moved between Macs. Create a new portable profile to use export/import."
        case .exportCancelled:
            return "Account export was cancelled."
        case .importCancelled:
            return "Account import was cancelled."
        case .unsupportedArchiveFormat:
            return "The recovery archive format is not supported by this build."
        case .chatBackupUsedForRecovery:
            return "This file is an encrypted chat backup. Recover the account first, then use Restore chat backup."
        }
    }
}

enum AccountPortability {
    static func exportArchiveData(
        identity: LocalIdentity,
        secret: String
    ) throws -> Data {
        guard identity.storageMode != "secure-enclave-v1" else {
            throw AccountPortabilityError.exportUnsupported
        }

        let archive = RecoveryTransferArchive(
            version: 1,
            exportedAt: NotrusCrypto.isoNow(),
            sourcePlatform: "macos",
            transferMode: "recovery-authorized-reset",
            identity: PortableArchiveIdentitySnapshot(identity: identity)
        )
        let plaintext = try JSONEncoder().encode(archive)
        let sealed = try NotrusCrypto.sealArchivePayload(
            plaintext,
            exportedAt: archive.exportedAt,
            secret: secret
        )
        return try JSONEncoder().encode(sealed)
    }

    static func exportArchive(
        identity: LocalIdentity,
        secret: String,
        to url: URL
    ) throws {
        let data = try exportArchiveData(
            identity: identity,
            secret: secret
        )
        try data.write(to: url, options: .atomic)
    }

    @MainActor
    static func revealExportedArchive(at url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    static func importArchive(from url: URL, secret: String) throws -> ImportedRecoveryArchivePayload {
        let sealed = try JSONDecoder().decode(EncryptedPortableAccountArchive.self, from: Data(contentsOf: url))
        let plaintext = try NotrusCrypto.openArchivePayload(sealed, secret: secret)
        let decoder = JSONDecoder()
        if let backup = try? decoder.decode(ChatBackupArchive.self, from: plaintext),
           backup.backupKind == ChatBackupPortability.backupKind {
            throw AccountPortabilityError.chatBackupUsedForRecovery
        }
        if let portable = try? decoder.decode(PortableAccountArchive.self, from: plaintext) {
            return .portable(portable)
        }
        if let transfer = try? decoder.decode(RecoveryTransferArchive.self, from: plaintext) {
            return .transfer(transfer)
        }
        throw AccountPortabilityError.unsupportedArchiveFormat
    }
}

enum ChatBackupPortability {
    static let backupKind = "notrus-chat-history-v1"

    static func exportBackupData(
        identity: LocalIdentity,
        threadRecords: [String: ThreadStoreRecord],
        secret: String
    ) throws -> Data {
        let backup = ChatBackupArchive(
            version: 1,
            exportedAt: NotrusCrypto.isoNow(),
            sourcePlatform: "macos",
            backupKind: backupKind,
            identity: ChatBackupIdentitySnapshot(identity: identity),
            attachmentsIncluded: false,
            threadRecords: threadRecords
        )
        let plaintext = try JSONEncoder().encode(backup)
        let sealed = try NotrusCrypto.sealArchivePayload(
            plaintext,
            exportedAt: backup.exportedAt,
            secret: secret
        )
        return try JSONEncoder().encode(sealed)
    }

    static func importBackup(from url: URL, secret: String) throws -> ChatBackupArchive {
        let sealed = try JSONDecoder().decode(EncryptedPortableAccountArchive.self, from: Data(contentsOf: url))
        let plaintext = try NotrusCrypto.openArchivePayload(sealed, secret: secret)
        let backup = try JSONDecoder().decode(ChatBackupArchive.self, from: plaintext)
        guard backup.backupKind == backupKind else {
            throw AccountPortabilityError.unsupportedArchiveFormat
        }
        return backup
    }
}
