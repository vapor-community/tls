import CLibreSSL

/**
    An SSL Socket.
*/
public final class Stream {
    public typealias CConfig = OpaquePointer
    public let socket: Int32
    public let cConfig: CConfig
    public let context: Context
    public let certificates: Certificates
    public let config: Config

    /**
         Creates a Socket from an SSL context and an
         unsecured socket's file descriptor.

         - parameter context: Re-usable SSL.Context in either Client or Server mode
         - parameter descriptor: The file descriptor from an unsecure socket already created.
    */
    public init(context: Context, config: Config, socket: Int32) throws {
        self.context = context
        self.config = config
        cConfig = tls_config_new()
        self.socket = socket

        self.certificates = config.certificates
        try loadCertificates(certificates)
        
        applyConfig()
        
        tls_configure(context.cContext, cConfig)
    }

    public convenience init(mode: Mode, socket: Int32, config: Config) throws {
        let context = try Context(mode: mode)
        try self.init(context: context, config: config, socket: socket)
    }
    
    private func applyConfig() {
        let conf = self.config
        
        if !conf.verifyCertificates || (context.mode == .server && conf.certificates.areSelfSigned) {
            print("[TLS] Warning: Self signed certificates prevent certificate verification.")
            tls_config_insecure_noverifycert(cConfig)
        }

        if !conf.verifyName {
            tls_config_insecure_noverifyname(cConfig)
        }
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
        case .none:
            break
        }
    }

    deinit {
        tls_config_free(cConfig)
    }


    /**
        Set a timeout for a given connection, in Seconds.
    */
    public func setTimeout(_ timeout: Int) throws {
        // FIXME
    }

    /**
         Connects to an SSL server from this client.

         This should only be called if the Context's mode is `.client`
    */
    public func connect(servername: String) throws {
        let result = tls_connect_socket(context.cContext, socket, servername)
        guard result == Result.OK else {
            throw TLSError.connect(context.error)
        }
    }

    /**
         Accepts a connection to this SSL server from a client.

         This should only be called if the Context's mode is `.server`
    */
    public func accept() throws {
        let result = tls_accept_socket(context.cContext, nil, socket)
        guard result == Result.OK else {
            throw TLSError.accept(context.error)
        }
    }

    /**
         Receives bytes from the secure socket.

         - parameter max: The maximum amount of bytes to receive.
    */
    public func receive(max: Int) throws -> [UInt8]  {
        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: max)
        defer {
            pointer.deallocate(capacity: max)
        }

        let result = tls_read(context.cContext, pointer, max)
        let bytesRead = Int(result)

        guard bytesRead >= 0 else {
            throw TLSError.receive(context.error)
        }


        let buffer = UnsafeBufferPointer<UInt8>.init(start: pointer, count: bytesRead)
        return Array(buffer)
    }

    /**
         Sends bytes to the secure socket.

         - parameter bytes: An array of bytes to send.
    */
    public func send(_ bytes: [UInt8]) throws {
        let buffer = UnsafeBufferPointer<UInt8>(start: bytes, count: bytes.count)

        let bytesSent = tls_write(context.cContext, buffer.baseAddress, bytes.count)

        guard bytesSent >= 0 else {
            throw TLSError.send(context.error)
        }
    }

    /**
        Sends a shutdown to secure socket
    */
    public func close() throws {
        let result = tls_close(context.cContext)
        guard result != -1 else { throw TLSError.close(context.error) }
    }
}
