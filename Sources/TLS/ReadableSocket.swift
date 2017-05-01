import CTLS

public protocol ReadableSocket: Socket, ReadableStream { }

extension ReadableSocket {
    /// Receives bytes from the secure socket.
    ///
    /// - parameter max: The maximum amount of bytes to receive.
    public func read(max: Int, into buffer: inout Bytes) throws -> Int  {
        let bytesRead = SSL_read(cSSL, &buffer, Int32(max))

        if bytesRead <= 0 {
            throw makeError(
                functionName: "SSL_read",
                returnCode: bytesRead
            )
        }

        return Int(bytesRead)
    }
}
