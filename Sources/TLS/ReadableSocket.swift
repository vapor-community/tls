import CTLS

public protocol ReadableSocket: Socket, ReadableStream { }

extension ReadableSocket {
    /// Receives bytes from the secure socket.
    ///
    /// - parameter max: The maximum amount of bytes to receive.
    public func read(max: Int) throws -> Bytes  {
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

        let buffer = UnsafeBufferPointer<Byte>.init(
            start: pointer,
            count: Int(bytesRead)
        )
        return Array(buffer)
    }
}
