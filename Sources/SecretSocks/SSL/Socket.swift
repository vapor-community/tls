import COpenSSL
import SocksCore

extension SSL {
    public final class Socket {
        public typealias CSSL = UnsafeMutablePointer<ssl_st>

        public let cSSL: CSSL

        init(context: Context, socket: SocksCore.Socket) throws {
            guard let ssl = SSL_new(context.cContext) else {
                throw Error.socketCreation(SSL.error)
            }

            SSL_set_fd(ssl, socket.descriptor)

            self.cSSL = ssl
        }

        deinit {
            SSL_shutdown(cSSL)
            SSL_free(cSSL)
        }

        public func connect() throws {
            guard SSL_connect(cSSL) == Result.OK else {
                throw Error.connect(SSL.error)
            }

        }

        public func accept() throws {
            guard SSL_accept(cSSL) == Result.OK else {
                throw Error.accept(SSL.error)
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
                throw Error.receive(SSL.error)
            }


            let buffer = UnsafeBufferPointer<UInt8>.init(start: pointer, count: bytesRead)
            return Array(buffer)
        }

        public func send(bytes: [UInt8]) throws {
            let buffer = UnsafeBufferPointer<UInt8>(start: bytes, count: bytes.count)

            let bytesSent = SSL_write(cSSL, buffer.baseAddress, bytes.count.int32)

            guard bytesSent >= 0 else {
                throw Error.send(SSL.error)
            }
        }
        
        // TODO: Verify connection
    }
}
