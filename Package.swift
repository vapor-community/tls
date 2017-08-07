// swift-tools-version:3.0
import PackageDescription

let package = Package(
    name: "TLS",
    dependencies: [
        .Package(url: "https://github.com/vapor/core.git", majorVersion: 2),
      	.Package(url: "https://github.com/vapor/sockets.git", majorVersion: 2),
        .Package(url: "https://github.com/vapor/ctls.git", majorVersion: 1),
    ]
)
