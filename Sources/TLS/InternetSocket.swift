import CTLS

public final class InternetSocket: Socket {
    public let socket: TCPInternetSocket
    public let context: Context
    public var cSSL: CSSL?

    public var client: TCPInternetSocket?

    public init(_ socket: TCPInternetSocket, _ context: Context) {
        self.socket = socket
        self.context = context
    }
    
    public func close() throws {
        try socket.close()
        try client?.close()
    }

    deinit {
        SSL_free(cSSL)
    }
}


// MARK: ProgramStream

extension InternetSocket: InternetStream {
    public var scheme: String {
        return socket.scheme
    }

    public var hostname: String {
        return socket.hostname
    }

    public var port: Port {
        return socket.port
    }
}

// MARK: Conformances

extension InternetSocket: ReadableSocket { }
extension InternetSocket: WriteableSocket { }

extension InternetSocket: ClientSocket { }
extension InternetSocket: ServerSocket { }
