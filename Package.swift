import PackageDescription

let beta1 = Version(1,0,0, prereleaseIdentifiers: ["beta"])
let beta2 = Version(2,0,0, prereleaseIdentifiers: ["beta"])

let package = Package(
    name: "TLS",
    dependencies: [
        .Package(url: "https://github.com/vapor/core.git", beta2),
      	.Package(url: "https://github.com/vapor/socks.git", beta2),
        .Package(url: "https://github.com/vapor/ctls.git", beta1),
    ]
)
