import CTLS
import Foundation
import Dispatch

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
    /// Dispatch Once is no longer a thing
    /// globally initialized vars guarantee same thread safety
    /// https://stackoverflow.com/a/37887068/2611971
    private static let isGloballyInitialized: Bool = {
        SSL_library_init()
        SSL_load_error_strings()
        OPENSSL_config(nil)
        OPENSSL_add_all_algorithms_conf()
        return true
    }()

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
        guard Context.isGloballyInitialized else { fatalError() }
        
        let method: CMethod
        switch mode {
        case .server:
            method = SSLv23_server_method()
        case .client:
            method = SSLv23_client_method()
        }

        guard let ctx = SSL_CTX_new(method) else {
            throw TLSError(
                functionName: "SSL_CTX_new",
                returnCode: nil,
                reason: "Unable to create new context"
            )
        }

        SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, nil)

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

        if !verifyCertificates || certificates.areSelfSigned {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
        }

        self.certificates = certificates
        self.cContext = ctx
        self.mode = mode
        self.verifyHost = verifyHost
        self.verifyCertificates = verifyCertificates

        try assert(
            SSL_CTX_set_cipher_list(ctx, cipherSuite ?? "DEFAULT"),
            functionName: "SSL_CTX_set_cipher_list"
        )

        try loadCertificates(certificates)
    }

    deinit {
        SSL_CTX_free(cContext)
    }
}

// MARK: Certificates

extension Context {
    /// Loads and sets the appropriate
    /// certificate files.
    internal func loadSignature(_ signature: Certificates.Signature) throws {
        switch signature {
        case .signedDirectory(caCertificateDirectory: let dir):
            try assert(
                SSL_CTX_load_verify_locations(cContext, nil, dir),
                functionName: "SSL_CTX_load_verify_locations"
            )
        case .signedFile(caCertificateFile: let file):
            try assert(
                SSL_CTX_load_verify_locations(cContext, file, nil),
                functionName: "SSL_CTX_load_verify_locations"
            )
        case .selfSigned:
            break
        }
    }

    internal func loadCertificates(_ certificates: Certificates) throws {
        switch certificates {
        case .chain(let file, let signature):
            try assert(
                SSL_CTX_use_certificate_chain_file(cContext, file),
                functionName: "SSL_CTX_use_certificate_chain_file"
            )

            try loadSignature(signature)
        case .files(let certFile, let keyFile, let signature):
            try assert(
                SSL_CTX_use_certificate_file(cContext, certFile, SSL_FILETYPE_PEM),
                functionName: "SSL_CTX_use_certificate_file"
            )

            try assert(
                SSL_CTX_use_PrivateKey_file(cContext, keyFile, SSL_FILETYPE_PEM),
                functionName: "SSL_CTX_use_PrivateKey_file"
            )

            try assert(
               SSL_CTX_check_private_key(cContext),
                functionName: "SSL_CTX_check_private_key"
            )

            try loadSignature(signature)
        case .certificateAuthority(let signature):
            try loadSignature(signature)
        case .bytes(var cert, var key, let signature):
            // cert
            guard let certBio = BIO_new_mem_buf(&cert, Int32(cert.count)) else {
                throw makeError(
                    functionName: "BIO_new_mem_buf",
                    returnCode: nil
                )
            }
            guard let cert = PEM_read_bio_X509(certBio, nil, nil, nil) else {
                throw makeError(
                    functionName: "PEM_read_bio_X509",
                    returnCode: nil
                )
            }
            try assert(
                SSL_CTX_use_certificate(cContext, cert),
                functionName: "SSL_CTX_use_certificate"
            )

            // key
            guard let keyBio = BIO_new_mem_buf(&key, Int32(key.count)) else {
                throw makeError(
                    functionName: "BIO_new_mem_buf",
                    returnCode: nil
                )
            }
            guard let key = PEM_read_bio_PrivateKey(keyBio, nil, nil, nil) else {
                throw makeError(
                    functionName: "PEM_read_bio_PrivateKey",
                    returnCode: nil
                )
            }
            try assert(
                SSL_CTX_use_PrivateKey(cContext, key),
                functionName: "SSL_CTX_use_PrivateKey"
            )

            try loadSignature(signature)
        case .none:
            break
        }
    }

}
