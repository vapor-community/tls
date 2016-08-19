import PackageDescription

let package = Package(
    name: "TLS",
    dependencies: [
    	.Package(url: "https://github.com/PerfectlySoft/Perfect-OpenSSL.git", majorVersion: 0, minor: 6),
    ]
)
