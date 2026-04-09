// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NotrusMac",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "NotrusMac", targets: ["NotrusMac"])
    ],
    targets: [
        .executableTarget(
            name: "NotrusMac",
            path: "Sources"
        ),
        .testTarget(
            name: "NotrusMacTests",
            dependencies: ["NotrusMac"],
            path: "Tests"
        )
    ]
)
