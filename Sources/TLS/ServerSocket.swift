import CTLS

/// A server SSL Socket.
public protocol ServerSocket: Socket, ServerStream {
    // keep from deallocating
    var client: TCPInternetSocket? { get set }
}

extension ServerSocket {
    /// Binds the socket to the address
    public func bind() throws {
        try socket.bind()
    }

    /// Starts listening on the socket
    public func listen(max: Int) throws {
        try socket.listen(max: max)
    }

    /// Accepts a connection to this SSL server from a client
    public func accept() throws -> Self {
        let client = try socket.accept()

        guard let ssl = SSL_new(context.cContext) else {
            throw makeError(functionName: "SSL_new")
        }
        cSSL = ssl

        try assert(
            SSL_set_fd(ssl, client.descriptor.raw),
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
        
        return self
    }
}
