import Foundation

enum NotrusBuildInfo {
    static let githubURL = URL(string: "https://github.com/Justbeginwithit/Notrus")!

    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.3.4"
    }

    static var buildNumber: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "dev"
    }

    static var buildCounter: String {
        Bundle.main.object(forInfoDictionaryKey: "NotrusBuildCounter") as? String ?? "dev"
    }

    static var buildID: String {
        Bundle.main.object(forInfoDictionaryKey: "NotrusBuildID") as? String ?? "\(version)+mac.\(buildNumber)"
    }
}
