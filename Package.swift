// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "TLS",
    products: [
        .library(name: "TLS", targets: ["TLS"]),
    ],
    dependencies: [
        // ⏱ Promises and reactive-streams in Swift built for high-performance and scalability.
        .package(url: "https://github.com/vapor/async.git", from: "1.0.0-rc"),

        // 🌎 Utility package containing tools for byte manipulation, Codable, OS APIs, and debugging.
        .package(url: "https://github.com/vapor/core.git", from: "3.0.0-rc"),

        // 🔌 Non-blocking TCP socket layer, with event-driven server and client.
        .package(url: "https://github.com/vapor/sockets.git", from: "3.0.0-rc"),
    ],
    targets: [
        .target(name: "TLS", dependencies: ["Async", "Bits", "Debugging", "TCP"]),
    ]
)

#if os(macOS)
    package.products.append(.library(name: "AppleTLS", targets: ["AppleTLS"]))
    package.targets.append(.target(name: "AppleTLS", dependencies: ["Async", "Bits", "Debugging", "TLS"]))
    package.targets.append(.testTarget(name: "TLSTests", dependencies: ["AppleTLS", "TLS"]))
#else
    package.products.append(.library(name: "OpenSSL", targets: ["OpenSSL"]))
    package.dependencies.append(.package(url: "https://github.com/vapor/copenssl.git", from: "1.0.0-rc"))
    package.targets.append(.target(name: "OpenSSL", dependencies: ["Async", "COpenSSL", "Debugging", "TLS"]))
    package.targets.append(.testTarget(name: "TLSTests", dependencies: ["OpenSSL", "TLS"]))
#endif
