import PackageDescription

let package = Package(
    name: "TLS",
    dependencies: [
    	.Package(url: "https://github.com/Zewo/COpenSSL", majorVersion: 0, minor: 6),
    ]
)
