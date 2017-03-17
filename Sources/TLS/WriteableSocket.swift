import CTLS

public protocol WriteableSocket: Socket, WriteableStream { }

// MARK: Writeable Stream

extension WriteableSocket {
    /// Sends bytes to the secure socket.
    ///
    /// - parameter bytes: An array of bytes to send.
    public func write(_ bytes: Bytes) throws {
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

    public func flush() throws {
        // no flush necessary
    }
}
