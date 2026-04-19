import DeviceCheck
import Foundation
import Security

enum DeviceRiskSignals {
    static func capture() async -> ClientIntegrityReport {
        let bundleIdentifier = Bundle.main.bundleIdentifier ?? "unknown-bundle"
        let codeSignatureStatus = evaluateCodeSignature()

        var deviceCheckStatus = "unsupported"
        var deviceCheckTokenPresented = false
        var note: String?

        if #available(macOS 10.15, *), DCDevice.current.isSupported {
            do {
                _ = try await DCDevice.current.generateToken()
                deviceCheckStatus = "token-issued"
                deviceCheckTokenPresented = true
            } catch {
                deviceCheckStatus = "token-error"
                note = error.localizedDescription
            }
        }

        let riskLevel: String
        switch (codeSignatureStatus, deviceCheckStatus) {
        case ("valid", "token-issued"):
            riskLevel = "low"
        case ("valid", _):
            riskLevel = "medium"
        default:
            riskLevel = "high"
        }

        return ClientIntegrityReport(
            bundleIdentifier: bundleIdentifier,
            codeSignatureStatus: codeSignatureStatus,
            deviceCheckStatus: deviceCheckStatus,
            deviceCheckTokenPresented: deviceCheckTokenPresented,
            generatedAt: NotrusCrypto.isoNow(),
            note: note,
            riskLevel: riskLevel
        )
    }

    private static func evaluateCodeSignature() -> String {
        var selfCode: SecCode?
        let copyStatus = SecCodeCopySelf([], &selfCode)
        guard copyStatus == errSecSuccess, let selfCode else {
            return "missing"
        }

        let validity = SecCodeCheckValidity(selfCode, [], nil)
        guard validity == errSecSuccess else {
            return "invalid"
        }

        return "valid"
    }
}
