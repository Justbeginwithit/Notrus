import SwiftUI
import UniformTypeIdentifiers

struct RecoveryArchiveDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    static var writableContentTypes: [UTType] { [.json] }

    var data: Data

    init(data: Data) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        self.data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

struct PreparedRecoveryArchiveExport {
    let defaultFileName: String
    let displayName: String
    let document: RecoveryArchiveDocument
}

struct PreparedChatBackupExport {
    let defaultFileName: String
    let displayName: String
    let document: RecoveryArchiveDocument
}
