import PackageDescription

let package = Package(
    name: "TLS",
    dependencies: [
    	.Package(url: "https://github.com/vapor/clibressl.git", majorVersion: 0, minor: 1),
    	.Package(url: "https://github.com/czechboy0/Socks.git", majorVersion: 0, minor: 12),
    ]
)
