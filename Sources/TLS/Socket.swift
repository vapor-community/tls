import CLibreSSL

/**
    An SSL Socket.
*/
public final class Socket {
    public let descriptor: Int32

    public let cConfig: OpaquePointer
    public let cContext: OpaquePointer


    /**
        Indicates whether or not an ssl connection received a shutdown.
    */
    public var closed: Bool {
        return false // FIXME
    }

    /**
         The current timeout associated with the socket.
    */
    public var timeout: Int {
        return 0 // FIXME
    }

    /**
         Creates a Socket from an SSL context and an
         unsecured socket's file descriptor.

         - parameter context: Re-usable SSL.Context in either Client or Server mode
         - parameter descriptor: The file descriptor from an unsecure socket already created.
    */
    public init(context: Context, descriptor: Int32) throws {
        tls_init()
        cConfig = tls_config_new()

        switch context.mode {
        case .server:
            cContext = tls_server()
        case .client:
            cContext = tls_client()
        }

        self.descriptor = descriptor
    }

    deinit {
        tls_free(cContext)
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
        let result = tls_connect_socket(cContext, descriptor, servername)
        guard result == Result.OK else {
            throw TLSError.connect(SocketError(result), error)
        }
    }

    /**
         Accepts a connection to this SSL server from a client.

         This should only be called if the Context's mode is `.server`
    */
    public func accept() throws {
        let result = tls_accept_socket(cContext, nil, descriptor)
        guard result == Result.OK else {
            throw TLSError.accept(SocketError(result), error)
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

        let result = tls_read(cContext, pointer, max)
        let bytesRead = Int(result)

        guard bytesRead >= 0 else {
            throw TLSError.receive(SocketError(result.int32), error)
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

        let bytesSent = tls_write(cContext, buffer.baseAddress, bytes.count)

        guard bytesSent >= 0 else {
            throw TLSError.send(SocketError(bytesSent.int32), error)
        }
    }

    /**
        Sends a shutdown to secure socket
    */
    public func close() throws {
        let result = tls_close(cContext)
        guard result != -1 else { throw TLSError.close(SocketError(result), error) }
    }
}
