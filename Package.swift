// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "TLS",
    products: [
        .library(name: "ServerSecurity", targets: ["ServerSecurity"]),
        .library(name: "TLS", targets: ["TLS"]),
    ],
    dependencies: [
        // Swift Promises, Futures, and Streams.
        .package(url: "https://github.com/vapor/async.git", "1.0.0-beta.1"..<"1.0.0-beta.2"),

        // Core extensions, type-aliases, and functions that facilitate common tasks.
        .package(url: "https://github.com/vapor/core.git", "3.0.0-beta.2"..<"3.0.0-beta.3"),

        // Pure Swift (POSIX) TCP and UDP non-blocking socket layer, with event-driven Server and Client.
        .package(url: "https://github.com/vapor/sockets.git", "3.0.0-beta.3"..<"3.0.0-beta.4"),
    ],
    targets: [
        .target(name: "ServerSecurity", dependencies: ["COperatingSystem", "TCP"]),
        .target(name: "TLS", dependencies: ["Async", "Bits", "Debugging", "TCP"]),
    ]
)

#if os(macOS)
    package.products.append(.library(name: "AppleTLS", targets: ["AppleTLS"]))
    package.targets.append(.target(name: "AppleTLS", dependencies: ["Async", "Bits", "Debugging", "TLS"]))
    package.targets.append(.testTarget(name: "TLSTests", dependencies: ["AppleTLS", "TLS"]))
#else
    package.products.append(.library(name: "OpenSSL", targets: ["OpenSSL"]))
    package.dependencies.append(.package(url: "https://github.com/vapor/copenssl.git", "1.0.0-beta.1"..<"1.0.0-beta.2"))
    package.targets.append(.target(name: "OpenSSL", dependencies: ["Async", "COpenSSL", "Debugging", "TLS"]))
    package.targets.append(.testTarget(name: "TLSTests", dependencies: ["OpenSSL", "TLS"]))
#endif
