import AppKit
import Foundation

enum AccountPortabilityError: LocalizedError, Equatable {
    case exportUnsupported
    case exportCancelled
    case importCancelled

    var errorDescription: String? {
        switch self {
        case .exportUnsupported:
            return "This profile was created with the older hardware-pinned format and cannot be moved between Macs. Create a new portable profile to use export/import."
        case .exportCancelled:
            return "Account export was cancelled."
        case .importCancelled:
            return "Account import was cancelled."
        }
    }
}

enum AccountPortability {
    static func exportArchiveData(
        identity: LocalIdentity,
        threadRecords: [String: ThreadStoreRecord],
        passphrase: String
    ) throws -> Data {
        guard identity.storageMode != "secure-enclave-v1" else {
            throw AccountPortabilityError.exportUnsupported
        }

        let archive = PortableAccountArchive(
            version: 1,
            exportedAt: NotrusCrypto.isoNow(),
            identity: identity,
            threadRecords: threadRecords
        )
        let sealed = try NotrusCrypto.sealPortableArchive(archive, passphrase: passphrase)
        return try JSONEncoder().encode(sealed)
    }

    static func exportArchive(
        identity: LocalIdentity,
        threadRecords: [String: ThreadStoreRecord],
        passphrase: String,
        to url: URL
    ) throws {
        let data = try exportArchiveData(
            identity: identity,
            threadRecords: threadRecords,
            passphrase: passphrase
        )
        try data.write(to: url, options: .atomic)
    }

    @MainActor
    static func revealExportedArchive(at url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    static func importArchive(from url: URL, passphrase: String) throws -> PortableAccountArchive {
        let sealed = try JSONDecoder().decode(EncryptedPortableAccountArchive.self, from: Data(contentsOf: url))
        return try NotrusCrypto.openPortableArchive(sealed, passphrase: passphrase)
    }
}
