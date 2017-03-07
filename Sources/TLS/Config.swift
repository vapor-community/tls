//import CTLS
//
///// Configuration for the TLS communication.
///// See http://man.openbsd.org/OpenBSD-current/man3/tls_init.3
//public final class Config {
//
//    
//    public typealias CConfig = OpaquePointer
//    
//    public let context: Context
//    
//    // public let cConfig: CConfig
//    
//    /// Specifies the used certificates.
//    /// (Client and Server)
//    public let certificates: Certificates
//    
//    /// Allows you to disable server name verification. Be careful when using this option.
//    /// (Client)
//    public let verifyHost: Bool
//    
//    /// Allows you to disable certificate verification. Be extremely careful when using this option.
//    /// (Client and Server)
//    public let verifyCertificates: Bool
//    
//    public init(
//        context: Context,
//        certificates: Certificates = .defaults,
//        verifyHost: Bool = true,
//        verifyCertificates: Bool = true,
//        cipher: Cipher = .compat,
//        proto: [Config.TLSProtocol] = [.all]
//    ) throws {
//        self.context = context
////        SSL_CTX_set_ecdh_auto(context.cContext, 1)
//
////        cConfig = tls_config_new()
////        
//
//
//        self.certificates = certificates
//        self.verifyHost = verifyHost
//        self.verifyCertificates = verifyCertificates
//        
//        try loadCertificates(certificates)
//        
////        if !verifyCertificates  {
////            tls_config_insecure_noverifycert(cConfig)
////        } else {
////            if case .none = certificates {
////                print("[TLS] Warning: No certificates were supplied. This may prevent TLS from successfully connecting unless the `verifyCertificates` option is set to false.")
////            }
////        }
////        
////        if !verifyHost {
////            tls_config_insecure_noverifyname(cConfig)
////        }
////        
////        guard tls_configure(context.cContext, cConfig) >= 0 else {
////            throw TLSError.configureFailed(context.error)
////        }
//    }
//    
//    public convenience init(
//        mode: Mode,
//        certificates: Certificates = .defaults,
//        verifyHost: Bool = true,
//        verifyCertificates: Bool = true
//    ) throws {
//        let context = try Context(mode: mode)
//        try self.init(
//            context: context,
//            certificates: certificates,
//            verifyHost: verifyHost,
//            verifyCertificates: verifyCertificates
//        )
//    }
//
//    deinit {
//        //tls_config_free(cConfig)
//    }
//    
//}
