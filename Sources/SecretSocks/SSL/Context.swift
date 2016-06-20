import COpenSSL

extension SSL {
    public final class Context {
        public typealias CContext = UnsafeMutablePointer<SSL_CTX>
        public let cContext: CContext

        public enum Verify {
            case none
            case peer
        }

        init(
            method: Method,
            mode: Mode,
            certificates: Certificates,
            cipherList: String,
            verify: Verify,
            verifyDepth: Int
            ) throws {
            guard let context = SSL_CTX_new(method) else {
                throw Error.contextCreation
            }

            if case .server = mode {
                SSL_CTX_ctrl(context, SSL_CTRL_OPTIONS, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION, nil)
            }

            cContext = context
            self.cipherList = cipherList
            self.verify = verify
            self.verifyDepth = verifyDepth

            // TODO: Verify files exist

            switch certificates {
            case .file(let caCertificateFile, let certificateFile, let privateKeyFile, _):
                try loadVerifyLocations(file: caCertificateFile)
                try useCertificate(file: certificateFile)
                try usePrivateKey(file: privateKeyFile)
            case .directory(let caCertificateDirectory, let certificateFile, let privateKeyFile, _):
                try loadVerifyLocations(directory: caCertificateDirectory)
                try useCertificate(file: certificateFile)
                try usePrivateKey(file: privateKeyFile)
            case .chain(let chainFile, _):
                try useCertificate(chain: chainFile)
            }
        }

        public var cipherList: String {
            didSet {
                SSL_CTX_set_cipher_list(cContext, cipherList)
            }
        }

        public var verify: Verify {
            didSet {
                switch verify {
                case .none:
                    SSL_CTX_set_verify(cContext, SSL_VERIFY_NONE, nil)
                case .peer:
                    SSL_CTX_set_verify(cContext, SSL_VERIFY_PEER, nil)
                }
            }

        }

        public var verifyDepth: Int {
            didSet {
                SSL_CTX_set_verify_depth(cContext, verifyDepth.int32)
            }
        }

        public func loadVerifyLocations(file caCertificateFile: String) throws {
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
            guard SSL_CTX_use_certificate_file(cContext, certificateFile, SSL_FILETYPE_PEM) == Result.OK else {
                throw Error.useCertificate(error)
            }
        }

        public func useCertificate(chain chainFile: String) throws {
            guard SSL_CTX_use_certificate_chain_file(cContext, chainFile) == Result.OK else {
                throw Error.useChain(error)
            }
        }


        public func usePrivateKey(file privateKeyFile: String) throws {
            guard SSL_CTX_use_PrivateKey_file(cContext, privateKeyFile, SSL_FILETYPE_PEM) == Result.OK else {
                throw Error.usePrivateKey(error)
            }

            guard SSL_CTX_check_private_key(cContext) == Result.OK else {
                throw Error.checkPrivateKey(error)
            }
        }
        
        
    }
}
