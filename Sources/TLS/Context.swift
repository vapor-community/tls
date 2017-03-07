import CTLS
import Foundation

public typealias CContext = UnsafeMutablePointer<SSL_CTX>
public typealias CMethod = UnsafePointer<SSL_METHOD>
public typealias CSSL = UnsafeMutablePointer<SSL>

/// An SSL context that contains the
/// optional certificates as well as references
/// to all initialized SSL libraries and configurations.
///
/// The context is used to create secure sockets and should
/// be reused when creating multiple sockets.
public final class Context {
    private static var isGloballyInitialized = false

    public let certificates: Certificates
    public let mode: Mode
    public var cContext: CContext
    public let verifyHost: Bool
    public let verifyCertificates: Bool

    
    /// Creates an SSL Context.
    ///
    /// - parameter mode: Client or Server.
    /// - parameter certificates: The certificates for the Client or Server.
    public init(
        _ mode: Mode,
        _ certificates: Certificates = .defaults,
        verifyHost: Bool = true,
        verifyCertificates: Bool = true,
        cipherSuite: String? = nil
    ) throws {
        if !Context.isGloballyInitialized {
            SSL_library_init()
            SSL_load_error_strings()
            OPENSSL_config(nil)
            OPENSSL_add_all_algorithms_conf()
            Context.isGloballyInitialized = true
        }
        
        let method: CMethod
        switch mode {
        case .server:
            method = SSLv23_server_method()
        case .client:
            method = SSLv23_client_method()
        }

        guard let ctx = SSL_CTX_new(method) else {
            throw "no context"
        }

        SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, nil)

        guard SSL_CTX_set_cipher_list(
            ctx,
            cipherSuite
                ?? "DEFAULT"
        ) == 1 else {
            throw "cipher problem"
        }

        if mode == .client {
            SSL_CTX_ctrl(
                ctx,
                SSL_CTRL_OPTIONS,
                SSL_OP_NO_SSLv2
                    | SSL_OP_NO_SSLv3
                    | SSL_OP_NO_COMPRESSION,
                nil
            )
        }

        if !verifyCertificates {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
        }

        //        let protocolsString = proto.count > 0 ? proto.map { $0.rawValue }.joined(separator: ",") : TLSProtocol.all.rawValue
        //        var protocols:UInt32 = 0
        //        guard tls_config_parse_protocols(&protocols, protocolsString) >= 0 else {
        //            throw TLSError.parsingProtocolsFailed(context.error)
        //        }
        //        tls_config_set_protocols(cConfig, protocols)
        //
        //        let cipherSetResult = tls_config_set_ciphers(cConfig, cipher.rawValue)
        //        guard cipherSetResult != -1 else {
        //            throw TLSError.cipherListFailed
        //        }

        self.certificates = certificates
        self.cContext = ctx
        self.mode = mode
        self.verifyHost = verifyHost
        self.verifyCertificates = verifyCertificates

        try loadCertificates(certificates)
    }

    deinit {
        SSL_CTX_free(cContext)
    }

    public var error: String {
        let err = ERR_get_error()
        if err == 0 {
            return "Unknown"
        }

        if let errorStr = ERR_reason_error_string(err) {
            return String(validatingUTF8: errorStr) ?? "Unknown"
        } else {
            return "Unknown"
        }
    }
}

// MARK: Certificates

extension Context {
    /// Loads and sets the appropriate
    /// certificate files.
    internal func loadSignature(_ signature: Certificates.Signature) throws {
        switch signature {
        case .signedDirectory(caCertificateDirectory: let dir):
            guard SSL_CTX_load_verify_locations(cContext, nil, dir) == 1 else {
                throw TLSError.setCAPath(path: dir, error)
            }
        case .signedFile(caCertificateFile: let file):
            guard SSL_CTX_load_verify_locations(cContext, file, nil) == 1 else {
                throw TLSError.setCAFile(file: file, error)
            }
        case .signedBytes(caCertificateBytes: var bytes):
            throw "unsupported signed bytes ca"
        case .selfSigned:
            break
        }
    }

    internal func loadCertificates(_ certificates: Certificates) throws {
        switch certificates {
        case .chain(let file, let signature):
            guard SSL_CTX_use_certificate_file(cContext, file, SSL_FILETYPE_PEM) == Result.OK else {
                throw TLSError.setCertificateFile(error)
            }
            try loadSignature(signature)
        case .files(let certFile, let keyFile, let signature):
            throw "not implemented"
//            guard tls_config_set_cert_file(cConfig, certFile) == Result.OK else {
//                throw TLSError.setCertificateFile(context.error)
//            }
//            guard tls_config_set_key_file(cConfig, keyFile) == Result.OK else {
//                throw TLSError.setKeyFile(context.error)
//            }
//            try loadSignature(signature)
        case .certificateAuthority(let signature):
            try loadSignature(signature)
        case .bytes(var cert, var key, let signature):
            let certBio = BIO_new_mem_buf(&cert, Int32(cert.count))
            let cert = PEM_read_bio_X509(certBio, nil, nil, nil)
            guard SSL_CTX_use_certificate(cContext, cert) == 1 else {
                throw TLSError.setCertificateBytes(error)
            }

            let keyBio = BIO_new_mem_buf(&key, Int32(key.count))
            let key = PEM_read_bio_PrivateKey(keyBio, nil, nil, nil)
            guard SSL_CTX_use_PrivateKey(cContext, key) == 1 else {
                throw TLSError.setKeyBytes(error)
            }
            try loadSignature(signature)
        case .none:
            break
        }
    }

}
