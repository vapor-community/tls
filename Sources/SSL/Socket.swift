import COpenSSL

public final class Socket {
    public typealias CSSL = UnsafeMutablePointer<ssl_st>

    public let cSSL: CSSL

    public init(context: Context, descriptor: Int32) throws {
        guard let ssl = SSL_new(context.cContext) else {
            throw Error.socketCreation(error)
        }

        SSL_set_fd(ssl, descriptor)

        self.cSSL = ssl
    }

    deinit {
        SSL_shutdown(cSSL)
        SSL_free(cSSL)
    }


    public func connect() throws {
        let result = SSL_connect(cSSL)
        guard result == Result.OK else {
            throw Error.connect(SocketError(result), error)
        }

    }

    public func accept() throws {
        let result = SSL_accept(cSSL)
        guard result == Result.OK else {
            throw Error.accept(SocketError(result), error)
        }
    }

    public func receive(max: Int) throws -> [UInt8]  {
        let pointer = UnsafeMutablePointer<UInt8>.init(allocatingCapacity: max)
        defer {
            pointer.deallocateCapacity(max)
        }

        let result = SSL_read(cSSL, pointer, max.int32)
        let bytesRead = Int(result)

        guard bytesRead >= 0 else {
            throw Error.receive(SocketError(result), error)
        }


        let buffer = UnsafeBufferPointer<UInt8>.init(start: pointer, count: bytesRead)
        return Array(buffer)
    }

    public func send(_ bytes: [UInt8]) throws {
        let buffer = UnsafeBufferPointer<UInt8>(start: bytes, count: bytes.count)

        let bytesSent = SSL_write(cSSL, buffer.baseAddress, bytes.count.int32)

        guard bytesSent >= 0 else {
            throw Error.send(SocketError(bytesSent), error)
        }
    }
    
    // TODO: Verify connection
}
