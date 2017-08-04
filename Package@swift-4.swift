// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "TLS",
    products: [
        .library(name: "TLS", targets: ["TLS"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/core.git", .upToNextMajor(from: "2.1.1")),
      	.package(url: "https://github.com/vapor/sockets.git", .upToNextMajor(from: "2.1.0")),
        .package(url: "https://github.com/vapor/ctls.git", .upToNextMajor(from: "1.0.0")),
    ],
    targets: [
        .target(name: "TLS", dependencies: ["Core", "Sockets", "CTLS"]),
        .testTarget(name: "TLSTests", dependencies: ["TLS"]),
    ]
)
