import COpenSSL

public final class Socket {
    public typealias CSSL = UnsafeMutablePointer<ssl_st>

    public let cSSL: CSSL

    public init(context: Context, socketDescriptor: Int32) throws {
        guard let ssl = SSL_new(context.cContext) else {
            throw Error.socketCreation(error)
        }

        SSL_set_fd(ssl, socketDescriptor)

        self.cSSL = ssl
    }

    deinit {
        SSL_shutdown(cSSL)
        SSL_free(cSSL)
    }

    public func errorFor(_ result: Int32) -> String {
        let r = SSL_get_error(cSSL, result)

        let string: String
        switch r {
        case SSL_ERROR_NONE:
            string = "None"
        case SSL_ERROR_ZERO_RETURN:
            string = "Zero return"
        case SSL_ERROR_WANT_READ:
            string = "Want read"
        case SSL_ERROR_WANT_WRITE:
            string = "Want write"
        case SSL_ERROR_WANT_CONNECT:
            string = "Want connect"
        case SSL_ERROR_WANT_ACCEPT:
            string = "Want accept"
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "Want x509 lookup"
        case SSL_ERROR_SYSCALL:
            string = "syscall"
        case SSL_ERROR_SSL:
            string = "ssl"
        default:
            string = "Unknown"
        }

        return string + " " + error
    }

    public func connect() throws {
        let result = SSL_connect(cSSL)
        guard result == Result.OK else {
            throw Error.connect(errorFor(result))
        }

    }

    public func accept() throws {
        let result = SSL_accept(cSSL)
        guard result == Result.OK else {
            throw Error.accept(errorFor(result))
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
            throw Error.receive(error)
        }


        let buffer = UnsafeBufferPointer<UInt8>.init(start: pointer, count: bytesRead)
        return Array(buffer)
    }

    public func send(_ bytes: [UInt8]) throws {
        let buffer = UnsafeBufferPointer<UInt8>(start: bytes, count: bytes.count)

        let bytesSent = SSL_write(cSSL, buffer.baseAddress, bytes.count.int32)

        guard bytesSent >= 0 else {
            throw Error.send(error)
        }
    }
    
    // TODO: Verify connection
}
