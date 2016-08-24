import PackageDescription

let package = Package(
    name: "TLS",
    dependencies: [
    	.Package(url: "https://github.com/Zewo/COpenSSL.git", majorVersion: 0, minor: 8),
    ]
)
