import CTLS

/// An SSL Socket.
public final class Socket {
    public let socket: TCPInternetSocket
    public let context: Context
    public var cSSL: CSSL?

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
//        let connectResult = tls_connect_socket(
//            config.context.cContext,
//            socket.descriptor,
//            servername
//        )

        let connectResult = SSL_connect(ssl)

        //currSocket = socket
        cSSL = ssl
        
        guard connectResult == 1 else {
            throw TLSError.connect(context.error)
        }

        guard let cert = SSL_get_peer_certificate(ssl) else {
            throw "No certificates"
        }


        let subject = X509_NAME_oneline(X509_get_subject_name(cert), nil, 0)
        let issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nil, 0)

        print(subject)
        print(issuer)

        free(subject)
        free(issuer)
        X509_free(cert)

        // handshake is performed automatically when using tls_read or tls_write, but by doing it here, handshake errors can be properly reported
        guard SSL_do_handshake(ssl) == Result.OK else {
            throw TLSError.handshake(context.error)
        }
    }
    
    /// Accepts a connection to this SSL server from a client.
    ///
    /// This should only be called if the Context's mode is `.server`
    public func accept() throws {
        let new = try socket.accept()
        print(new.descriptor)
        let ssl = SSL_new(context.cContext)
        SSL_set_fd(ssl, new.descriptor)

        // currSocket = new
        cSSL = ssl

        let result = SSL_accept(ssl)
        print(result)
        
        guard result == 1 else {
            try new.close()
            throw TLSError.accept(context.error)
        }
        
        // handshake is performed automatically when using tls_read or tls_write, but by doing it here, handshake errors can be properly reported
        guard SSL_do_handshake(ssl) == 1 else {
            try new.close()
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
        
        let result = SSL_read(cSSL, pointer, Int32(max))
        let bytesRead = Int(result)
        
        guard bytesRead >= 0 else {
            throw TLSError.receive(context.error)
        }
        
        let buffer = UnsafeBufferPointer<UInt8>.init(start: pointer, count: bytesRead)
        return Array(buffer)
    }
    
    /// Sends bytes to the secure socket.
    ///
    /// - parameter bytes: An array of bytes to send.
    public func send(_ bytes: Bytes) throws {
        print("TLS send")
        var bytes = bytes
        print("TLS enter while")
        print("here")
        let bytesSent = SSL_write(
            cSSL,
            &bytes,
            Int32(bytes.count)
        )
        print("there")
        print(bytesSent)

        if bytesSent <= 0 {
            let res = SSL_get_error(cSSL, bytesSent)
            print(res)
            throw TLSError.send(context.error)
        }
    }
    
    ///Sends a shutdown to secure socket
    public func close() throws {
        SSL_free(cSSL)
        // try currSocket?.close()
    }
}
