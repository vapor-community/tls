import TCP

public protocol TLSClient {
    func connect(hostname: String, port: UInt16) throws
}

/// MARK: Settings

public struct TLSClientSettings {
    public var clientCertificate: String?
    public var trustedCAFilePaths: [String]
    public var peerDomainName: String?

    public init() {
        trustedCAFilePaths = []
    }
}
