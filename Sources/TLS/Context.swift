import COpenSSL
import Foundation

/**
    An SSL context that contains the
    optional certificates as well as references
    to all initialized SSL libraries and configurations.

    The context is used to create secure sockets and should
    be reused when creating multiple sockets.
*/

#if !os(Linux)
    // Temporary workaround to name differences on Linux and Mac
    typealias NSFileManager = FileManager
#endif

public final class Context {
    public typealias CContext = UnsafeMutablePointer<SSL_CTX>
    public let cContext: CContext

    public let certificates: Certificates

    public let mode: Mode

    /**
        Creates an SSL Context.

        - parameter mode: Client or Server.
        - parameter certificates: The certificates for the Client or Server.
        - parameter verifyDepth: Sets the maximum depth for the certificate chain verification that shall be allowed for ssl.
        - parameter cipherList: Sets the list of available ciphers for the context using the control string str
            Read more: https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_cipher_list.html
    */
    public init(
        mode: Mode,
        certificates: Certificates,
        verifyDepth: Int = 2,
        cipherList: String = "ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL"
    ) throws {
        SSL_library_init()
        SSL_load_error_strings()
        OPENSSL_config(nil)
        OPENSSL_add_all_algorithms_conf()

        let method = try Method(mode: mode)

        guard let context = SSL_CTX_new(method.cMethod) else {
            throw TLSError.contextCreation
        }

        cContext = context
        self.certificates = certificates
        self.mode = mode

        SSL_CTX_set_cipher_list(cContext, cipherList)

        if certificates.areSelfSigned {
            SSL_CTX_set_verify(cContext, SSL_VERIFY_NONE, nil)
        } else {
            SSL_CTX_set_verify(cContext, SSL_VERIFY_PEER, nil)
        }

        SSL_CTX_set_verify_depth(cContext, verifyDepth.int32)


        if case .client = mode {
            SSL_CTX_ctrl(context, SSL_CTRL_OPTIONS, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION, nil)
        }

        switch certificates {
        case .none:
            break
        case .files(let certificateFile, let privateKeyFile, let signature):
            try loadVerifySignature(signature)
            try useCertificate(file: certificateFile)
            try usePrivateKey(file: privateKeyFile)
        case .chain(let chainFile, let signature):
            try loadVerifySignature(signature)
            try useCertificate(chain: chainFile)
        }
    }

    /**
        Frees any resources allocated by SSL.
    */
    deinit {
        SSL_CTX_free(cContext)

        ERR_free_strings()
        EVP_cleanup()
    }

    /**
        Verifies that a file exists at the supplied path.
    */
    public func verifyFile(_ filePath: String) throws {
        guard NSFileManager.fileExists(at: filePath) else {
            throw TLSError.file("\(filePath) doesn't exist.")
        }
    }

    /**
        Loads and verifies the signature.
        Does not verify case `.selfSigned`.
    */
    public func loadVerifySignature(_ signature: Certificates.Signature) throws {
        switch signature {
        case .selfSigned:
            break
        case .signedDirectory(let caCertificateDirectory):
            try loadVerifyLocations(directory: caCertificateDirectory)
        case .signedFile(let caCertificateFile):
            try loadVerifyLocations(file: caCertificateFile)
        }
    }

    /**
        Calls `SSL_CTX_load_verify_locations` for paths.
        Learn more: https://wiki.openssl.org/index.php/Manual:SSL_CTX_load_verify_locations(3)
    */
    public func loadVerifyLocations(file caCertificateFile: String) throws {
        try verifyFile(caCertificateFile)

        guard SSL_CTX_load_verify_locations(cContext, caCertificateFile, nil) == Result.OK else {
            throw TLSError.loadCACertificate(error)
        }
    }

    /**
        Calls `SSL_CTX_load_verify_locations` for directories.
        Learn more: https://wiki.openssl.org/index.php/Manual:SSL_CTX_load_verify_locations(3)
    */
    public func loadVerifyLocations(directory caCertificateDirectory: String) throws {
        guard SSL_CTX_load_verify_locations(cContext, nil, caCertificateDirectory) == Result.OK else {
            throw TLSError.loadCACertificate(error)
        }
    }

    /**
        Loads the pem formatted certificate.

        Calls `SSL_CTX_use_certificate_file`.
        Learn more: https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_use_certificate.html
    */
    public func useCertificate(file certificateFile: String) throws {
        try verifyFile(certificateFile)

        guard SSL_CTX_use_certificate_file(cContext, certificateFile, SSL_FILETYPE_PEM) == Result.OK else {
            throw TLSError.useCertificate(error)
        }
    }

    /**
        Loads a certificate chain.

        Calls `SSL_CTX_use_certificate_chain_file`.
        Learn more: https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_use_certificate.html
    */
    public func useCertificate(chain chainFile: String) throws {
        try verifyFile(chainFile)

        guard SSL_CTX_use_certificate_chain_file(cContext, chainFile) == Result.OK else {
            throw TLSError.useChain(error)
        }
    }

    /**
        Loads and checks the pem formatted private key.

        Calls `SSL_CTX_use_PrivateKey_file` and `SSL_CTX_check_private_key`
        Learn more: https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_use_certificate.html
    */
    public func usePrivateKey(file privateKeyFile: String) throws {
        try verifyFile(privateKeyFile)

        guard SSL_CTX_use_PrivateKey_file(cContext, privateKeyFile, SSL_FILETYPE_PEM) == Result.OK else {
            throw TLSError.usePrivateKey(error)
        }

        guard SSL_CTX_check_private_key(cContext) == Result.OK else {
            throw TLSError.checkPrivateKey(error)
        }
    }
}
