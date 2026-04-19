import Foundation

enum TransportSecurityError: LocalizedError {
    case insecureOrigin(String)
    case invalidOrigin

    var errorDescription: String? {
        switch self {
        case .insecureOrigin(let origin):
            return "Notrus Mac only allows `http://localhost` and `http://127.0.0.1` for local development. Use HTTPS for relay URLs such as \(origin)."
        case .invalidOrigin:
            return "The relay URL is invalid."
        }
    }
}

enum TransportSecurityPolicy {
    private static let localDevelopmentHosts = Set(["127.0.0.1", "localhost", "::1"])
    static let requestTimeout: TimeInterval = 12
    static let resourceTimeout: TimeInterval = 20
    static let witnessTimeout: TimeInterval = 5

    static func validatedRelayOrigin(_ origin: String) throws -> URL {
        guard
            let url = URL(string: origin.trimmingCharacters(in: .whitespacesAndNewlines)),
            let scheme = url.scheme?.lowercased(),
            let host = url.host?.lowercased()
        else {
            throw TransportSecurityError.invalidOrigin
        }

        if scheme == "https" {
            return url
        }

        if scheme == "http", localDevelopmentHosts.contains(host) {
            return url
        }

        throw TransportSecurityError.insecureOrigin(origin)
    }

    static func isLocalDevelopmentOrigin(_ origin: String) -> Bool {
        guard
            let url = try? validatedRelayOrigin(origin),
            url.scheme?.lowercased() == "http"
        else {
            return false
        }
        return true
    }

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.waitsForConnectivity = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = resourceTimeout
        return URLSession(configuration: configuration)
    }
}
