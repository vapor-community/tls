
/// Configuration for the TLS communication.
/// See http://man.openbsd.org/OpenBSD-current/man3/tls_init.3
public struct Config {
    
    /// Specifies the used certificates.
    /// (Client and Server)
    public var certificates: Certificates = .none
    
    /// Allows you to disable server name verification. Be careful when using this option.
    /// (Client)
    public var verifyName: Bool = true
    
    /// Allows you to disable certificate verification. Be extremely careful when using this option.
    /// (Client and Server)
    public var verifyCertificates: Bool = true
    
    public init() { }
}
