import PackageDescription

let package = Package(
    name: "TLS",
    dependencies: [
    	.Package(url: "https://github.com/PerfectlySoft/Perfect-COpenSSL.git", majorVersion: 0, minor: 7),
    ]
)
