import CLibreSSL

/// Configuration for the TLS communication.
/// See http://man.openbsd.org/OpenBSD-current/man3/tls_init.3
public final class Config {
    public enum Cipher: String {
        case secure
        case compat
        case legacy
        case insecure
    }

    public typealias CConfig = OpaquePointer

    public let context: Context

    public let cConfig: CConfig
    
    /// Specifies the used certificates.
    /// (Client and Server)
    public let certificates: Certificates
    
    /// Allows you to disable server name verification. Be careful when using this option.
    /// (Client)
    public let verifyHost: Bool
    
    /// Allows you to disable certificate verification. Be extremely careful when using this option.
    /// (Client and Server)
    public let verifyCertificates: Bool
    
    public init(
        context: Context,
        certificates: Certificates = .mozilla,
        verifyHost: Bool = true,
        verifyCertificates: Bool = true,
        cipher: Cipher = .compat
    ) throws {
        self.context = context

        cConfig = tls_config_new()

        let cipherSetResult = tls_config_set_ciphers(cConfig, cipher.rawValue)
        guard cipherSetResult != -1 else {
            throw TLSError.cipherListFailed
        }

        self.certificates = certificates
        self.verifyHost = verifyHost
        self.verifyCertificates = verifyCertificates

        try loadCertificates(certificates)

        if !verifyCertificates  {
            tls_config_insecure_noverifycert(cConfig)
        } else {
            if case .none = certificates {
                print("[TLS] Warning: No certificates were supplied. This may prevent TLS from successfully connecting unless the `verifyCertificates` option is set to false.")
            }
        }

        if !verifyHost {
            tls_config_insecure_noverifyname(cConfig)
        }

        tls_configure(context.cContext, cConfig)
    }

    public convenience init(
        mode: Mode,
        certificates: Certificates = .mozilla,
        verifyHost: Bool = true,
        verifyCertificates: Bool = true
    ) throws {
        let context = try Context(mode: mode)
        try self.init(
            context: context,
            certificates: certificates,
            verifyHost: verifyHost,
            verifyCertificates: verifyCertificates
        )
    }

    /**
        Loads and sets the appropriate
        certificate files.
    */
    private func loadSignature(_ signature: Certificates.Signature) throws {
        switch signature {
        case .signedDirectory(caCertificateDirectory: let dir):
            guard tls_config_set_ca_path(cConfig, dir) == Result.OK else {
                throw TLSError.setCAPath(path: dir, context.error)
            }
        case .signedFile(caCertificateFile: let file):
            guard tls_config_set_ca_file(cConfig, file) == Result.OK else {
                throw TLSError.setCAFile(file: file, context.error)
            }
        case .signedBytes(caCertificateBytes: let bytes):
            guard tls_config_set_ca_mem(cConfig, bytes, bytes.count) == Result.OK else {
                throw TLSError.setCABytes(context.error)
            }
        case .selfSigned:
            break
        }
    }

    private func loadCertificates(_ certificates: Certificates) throws {
        switch certificates {
        case .chain(let file, let signature):
            guard tls_config_set_cert_file(cConfig, file) == Result.OK else {
                throw TLSError.setCertificateFile(context.error)
            }
            try loadSignature(signature)
        case .files(let certFile, let keyFile, let signature):
            guard tls_config_set_cert_file(cConfig, certFile) == Result.OK else {
                throw TLSError.setCertificateFile(context.error)
            }
            guard tls_config_set_key_file(cConfig, keyFile) == Result.OK else {
                throw TLSError.setKeyFile(context.error)
            }
            try loadSignature(signature)
        case .certificateAuthority(let signature):
            try loadSignature(signature)
        case .bytes(certificateBytes: let cert, keyBytes: let key, signature: let signature):
            guard tls_config_set_cert_mem(cConfig, cert, cert.count) == Result.OK else {
                throw TLSError.setCertificateBytes(context.error)
            }
            guard tls_config_set_key_mem(cConfig, key, key.count) == Result.OK else {
                throw TLSError.setKeyBytes(context.error)
            }
            try loadSignature(signature)
        case .none:
            break
        }
    }

    deinit {
        tls_config_free(cConfig)
    }

}
