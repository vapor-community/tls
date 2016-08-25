
/// Configuration for the TLS communication.
/// See http://man.openbsd.org/OpenBSD-current/man3/tls_init.3
/// TODO: This could also contain Certificates
public struct TLSConfig {
    
    /// Allows you to disable server name verification. Be careful when using this option.
    /// (Client)
    public var verifyName: Bool = true
    
    public init() { }
}

extension TLSConfig: Equatable {
    public static func ==(lhs: TLSConfig, rhs: TLSConfig) -> Bool {
        return lhs.verifyName == rhs.verifyName
    }
}
