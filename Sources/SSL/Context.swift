import COpenSSL
import Foundation

public final class Context {
    public typealias CContext = UnsafeMutablePointer<SSL_CTX>
    public let cContext: CContext

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
            throw Error.contextCreation
        }

        cContext = context

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
            try verifySignature(signature)
            try useCertificate(file: certificateFile)
            try usePrivateKey(file: privateKeyFile)
        case .chain(let chainFile, let signature):
            try verifySignature(signature)
            try useCertificate(chain: chainFile)
        }
    }

    deinit {
        SSL_CTX_free(cContext)

        ERR_free_strings()
        EVP_cleanup()
    }

    public func verifyFile(_ file: String) throws {
        guard NSFileManager.default().fileExists(atPath: file) else {
            throw Error.file("\(file) doesn't exist.")
        }
    }

    public func verifySignature(_ signature: Certificates.Signature) throws {
        switch signature {
        case .selfSigned:
            break
        case .signedDirectory(let caCertificateDirectory):
            try loadVerifyLocations(directory: caCertificateDirectory)
        case .signedFile(let caCertificateFile):
            try loadVerifyLocations(file: caCertificateFile)
        }
    }

    public func loadVerifyLocations(file caCertificateFile: String) throws {
        try verifyFile(caCertificateFile)

        guard SSL_CTX_load_verify_locations(cContext, caCertificateFile, nil) == Result.OK else {
            throw Error.loadCACertificate(error)
        }
    }

    public func loadVerifyLocations(directory caCertificateDirectory: String) throws {
        guard SSL_CTX_load_verify_locations(cContext, nil, caCertificateDirectory) == Result.OK else {
            throw Error.loadCACertificate(error)
        }
    }

    public func useCertificate(file certificateFile: String) throws {
        try verifyFile(certificateFile)

        guard SSL_CTX_use_certificate_file(cContext, certificateFile, SSL_FILETYPE_PEM) == Result.OK else {
            throw Error.useCertificate(error)
        }
    }

    public func useCertificate(chain chainFile: String) throws {
        try verifyFile(chainFile)

        guard SSL_CTX_use_certificate_chain_file(cContext, chainFile) == Result.OK else {
            throw Error.useChain(error)
        }
    }


    public func usePrivateKey(file privateKeyFile: String) throws {
        try verifyFile(privateKeyFile)

        guard SSL_CTX_use_PrivateKey_file(cContext, privateKeyFile, SSL_FILETYPE_PEM) == Result.OK else {
            throw Error.usePrivateKey(error)
        }

        guard SSL_CTX_check_private_key(cContext) == Result.OK else {
            throw Error.checkPrivateKey(error)
        }
    }

}
