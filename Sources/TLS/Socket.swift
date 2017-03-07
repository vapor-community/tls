import CTLS

/// An SSL Socket.
public final class Socket {
    public let socket: TCPInternetSocket
    public let context: Context
    public var cSSL: CSSL?
    public var currentSocket: TCPInternetSocket?

    /// Creates a Socket from an SSL context and an
    /// unsecured socket's file descriptor.
    ///
    /// - parameter context: Re-usable SSL.Context in either Client or Server mode
    /// - parameter descriptor: The file descriptor from an unsecure socket already created.
    public init(_ context: Context, _ socket: TCPInternetSocket) throws {
        self.context = context
        self.socket = socket
    }
    
    // public var currSocket: TCPInternetSocket?
    
    public convenience init(
        mode: Mode,
        hostname: String,
        port: UInt16 = 443,
        certificates: Certificates = .defaults,
        verifyHost: Bool = true,
        verifyCertificates: Bool = true,
        cipherSuite: String? = nil
    ) throws {
        let context = try Context(
            mode,
            certificates,
            verifyHost: verifyHost,
            verifyCertificates: verifyCertificates,
            cipherSuite: cipherSuite
        )
        
        let address = InternetAddress(hostname: hostname, port: port)
        let socket = try TCPInternetSocket(address: address)
        
        try self.init(context, socket)
    }
    
    
    /// Connects to an SSL server from this client.
    ///
    /// This should only be called if the Context's mode is `.client`
    public func connect(servername: String) throws {
        try socket.connect()

        let ssl = SSL_new(context.cContext)
        SSL_set_fd(ssl, socket.descriptor)
        cSSL = ssl

        if context.verifyHost {
            let param = SSL_get0_param(ssl)
            X509_VERIFY_PARAM_set_hostflags(
                param,
                UInt32(X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS)
            )
            X509_VERIFY_PARAM_set1_host(param, servername, 0);
            SSL_set_verify(ssl, SSL_VERIFY_PEER, nil)
        }
        
        guard SSL_connect(ssl) == 1 else {
            throw TLSError.connect(context.error)
        }

        guard SSL_do_handshake(ssl) == 1 else {
            throw TLSError.handshake(context.error)
        }
    }
    
    /// Accepts a connection to this SSL server from a client.
    ///
    /// This should only be called if the Context's mode is `.server`
    public func accept() throws {
        let client = try socket.accept()

        let ssl = SSL_new(context.cContext)
        SSL_set_fd(ssl, client.descriptor)
        currentSocket = client
        cSSL = ssl

        let result = SSL_accept(ssl)
        print(result)
        
        guard result == 1 else {
            try client.close()
            throw TLSError.accept(context.error)
        }

        print("before handshake")
        
        // handshake is performed automatically when using tls_read or tls_write, but by doing it here, handshake errors can be properly reported
        guard SSL_do_handshake(ssl) == 1 else {
            try client.close()
            throw TLSError.handshake(context.error)
        }
        print("handshake done")
    }
    
    /// Receives bytes from the secure socket.
    ///
    /// - parameter max: The maximum amount of bytes to receive.
    public func receive(max: Int) throws -> [UInt8]  {
        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: max)
        defer {
            pointer.deallocate(capacity: max)
        }

        let bytesRead = SSL_read(cSSL, pointer, Int32(max))
        
        if bytesRead <= 0 {
            print(bytesRead)
            let res = SSL_get_error(cSSL, bytesRead)
            print(res)
            print(String(validatingUTF8: strerror(errno))!)
            throw TLSError.receive(context.error)
        }
        
        let buffer = UnsafeBufferPointer<UInt8>.init(start: pointer, count: Int(bytesRead))
        return Array(buffer)
    }
    
    /// Sends bytes to the secure socket.
    ///
    /// - parameter bytes: An array of bytes to send.
    public func send(_ bytes: Bytes) throws {
        var totalBytesSent = 0
        let buffer = UnsafeBufferPointer<UInt8>(start: bytes, count: bytes.count)
        guard let bufferBaseAddress = buffer.baseAddress else {
            throw TLSError.send("Failed to get buffer base address")
        }

        while totalBytesSent < bytes.count {
            let bytesSent = SSL_write(
                cSSL,
                bufferBaseAddress.advanced(by: totalBytesSent),
                Int32(bytes.count - totalBytesSent)
            )
            if bytesSent <= 0 {
                throw TLSError.send(context.error)
            }

            totalBytesSent += Int(bytesSent)
        }
    }
    
    ///Sends a shutdown to secure socket
    public func close() throws {
        SSL_free(cSSL)
        try currentSocket?.close()
    }
}
