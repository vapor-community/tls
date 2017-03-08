import CTLS
import Socks

/// An SSL Socket.
public final class Socket {
    public let socket: TCPInternetSocket
    public let context: Context
    public var cSSL: CSSL?

    // keep from deallocating
    public var client: TCPInternetSocket?

    /// Creates a Socket from an SSL context and an
    /// unsecured socket's file descriptor.
    ///
    /// - parameter context: Re-usable SSL.Context in either Client or Server mode
    /// - parameter descriptor: The file descriptor from an unsecure socket already created.
    public init(_ context: Context, _ socket: TCPInternetSocket) throws {
        self.context = context
        self.socket = socket
    }
    
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

        guard let ssl = SSL_new(context.cContext) else {
            throw makeError(functionName: "SSL_new")
        }
        cSSL = ssl

        try assert(
            SSL_set_fd(ssl, socket.descriptor),
            functionName: "SSL_set_fd"
        )

        if context.verifyHost {
            print("Warning: Host verification not implemented.")
//            let param = SSL_get0_param(ssl)
//            X509_VERIFY_PARAM_set_hostflags(
//                param,
//                UInt32(X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS)
//            )
//            X509_VERIFY_PARAM_set1_host(param, servername, 0);
//            SSL_set_verify(ssl, SSL_VERIFY_PEER, nil)
        }

        try assert(
            SSL_connect(ssl),
            functionName: "SSL_connect"
        )

        try assert(
            SSL_do_handshake(ssl),
            functionName: "SSL_do_handshake"
        )
    }
    
    /// Accepts a connection to this SSL server from a client.
    ///
    /// This should only be called if the Context's mode is `.server`
    public func accept() throws {
        let client = try socket.accept()

        guard let ssl = SSL_new(context.cContext) else {
            throw makeError(functionName: "SSL_new")
        }
        cSSL = ssl

        try assert(
            SSL_set_fd(ssl, client.descriptor),
            functionName: "SSL_set_fd"
        )
        // keep from deallocating
        self.client = client

        try assert(
            SSL_accept(ssl),
            functionName: "SSL_accept"
        )

        try assert(
            SSL_do_handshake(ssl),
            functionName: "SSL_do_handshake"
        )
    }
    
    /// Receives bytes from the secure socket.
    ///
    /// - parameter max: The maximum amount of bytes to receive.
    public func receive(max: Int) throws -> Bytes  {
        let pointer = UnsafeMutablePointer<Byte>
            .allocate(capacity: max)
        defer {
            pointer.deallocate(capacity: max)
        }

        let bytesRead = SSL_read(cSSL, pointer, Int32(max))
        
        if bytesRead <= 0 {
            throw makeError(
                functionName: "SSL_read",
                returnCode: bytesRead
            )
        }
        
        let buffer = UnsafeBufferPointer<UInt8>.init(start: pointer, count: Int(bytesRead))
        return Array(buffer)
    }
    
    /// Sends bytes to the secure socket.
    ///
    /// - parameter bytes: An array of bytes to send.
    public func send(_ bytes: Bytes) throws {
        var totalBytesSent = 0
        let buffer = UnsafeBufferPointer<Byte>(start: bytes, count: bytes.count)
        guard let bufferBaseAddress = buffer.baseAddress else {
            throw TLSError(
                functionName: "baseAddress",
                returnCode: nil,
                reason: "Could not fetch buffer base address"
            )
        }

        while totalBytesSent < bytes.count {
            let bytesSent = SSL_write(
                cSSL,
                bufferBaseAddress.advanced(by: totalBytesSent),
                Int32(bytes.count - totalBytesSent)
            )
            if bytesSent <= 0 {
                throw makeError(
                    functionName: "SSL_write",
                    returnCode: bytesSent
                )
            }

            totalBytesSent += Int(bytesSent)
        }
    }

    deinit {
        SSL_free(cSSL)
    }
    
    ///Sends a shutdown to secure socket
    public func close() throws {
        try client?.close()
    }
}
