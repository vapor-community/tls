import CTLS

/// A server SSL Socket.
public final class ServerSocket: Socket, ServerStream {
    public static let mode = Mode.server

    public let socket: TCPInternetSocket
    public let context: Context
    public var cSSL: CSSL?

    public init(_ socket: TCPInternetSocket, _ context: Context) {
        self.socket = socket
        self.context = context
    }

    // keep from deallocating
    public var client: TCPInternetSocket?

    /// Binds the socket to the address
    public func bind() throws {
        try socket.bind()
    }

    /// Starts listening on the socket
    public func listen(max: Int) throws {
        try socket.listen(max: max)
    }

    /// Accepts a connection to this SSL server from a client
    public func accept() throws -> ServerSocket {
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

    deinit {
        try? client?.close()
        SSL_free(cSSL)
    }
}
