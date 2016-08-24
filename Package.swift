import PackageDescription

let package = Package(
    name: "TLS",
    dependencies: [
    	.Package(url: "https://github.com/vapor/clibressl.git", Version(0,1,9)),
    ]
)
