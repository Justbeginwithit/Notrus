import AppKit
import Foundation
import UniformTypeIdentifiers

enum AttachmentGatewayError: LocalizedError {
    case emptySelection
    case importCancelled
    case oversized(String, Int)
    case saveCancelled

    var errorDescription: String? {
        switch self {
        case .emptySelection:
            return "Choose at least one file to attach."
        case .importCancelled:
            return "Attachment import was cancelled."
        case .oversized(let fileName, let maxBytes):
            return "\(fileName) is larger than the current safe attachment limit of \(maxBytes / (1024 * 1024)) MB."
        case .saveCancelled:
            return "Attachment save was cancelled."
        }
    }
}

enum AttachmentGateway {
    static let maxAttachmentBytes = 25 * 1024 * 1024

    static func importAttachments() throws -> [LocalAttachmentDraft] {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = true
        panel.title = "Attach Encrypted Files"
        panel.message = "Choose files to encrypt before upload. Notrus will not preview or auto-open them."
        guard panel.runModal() == .OK else {
            throw AttachmentGatewayError.importCancelled
        }

        guard !panel.urls.isEmpty else {
            throw AttachmentGatewayError.emptySelection
        }

        return try panel.urls.map { url in
            let values = try url.resourceValues(forKeys: [.contentTypeKey, .fileSizeKey, .nameKey])
            let byteLength = values.fileSize ?? 0
            let fileName = sanitizedFileName(values.name ?? url.lastPathComponent)
            if byteLength > maxAttachmentBytes {
                throw AttachmentGatewayError.oversized(fileName, maxAttachmentBytes)
            }

            return LocalAttachmentDraft(
                id: UUID().uuidString.lowercased(),
                byteLength: byteLength,
                fileName: fileName,
                mediaType: values.contentType?.preferredMIMEType ?? "application/octet-stream",
                url: url
            )
        }
    }

    static func saveAttachment(data: Data, reference: SecureAttachmentReference) throws {
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = sanitizedFileName(reference.fileName)
        panel.title = "Save Decrypted Attachment"
        panel.message = "Notrus will write the decrypted bytes to the location you choose. The file will not be previewed or opened automatically."
        guard panel.runModal() == .OK, let url = panel.url else {
            throw AttachmentGatewayError.saveCancelled
        }

        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static func sanitizedFileName(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
        let filtered = String(trimmed.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" })
        return filtered.isEmpty ? "attachment.bin" : filtered
    }
}
