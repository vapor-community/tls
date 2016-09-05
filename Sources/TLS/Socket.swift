import CLibreSSL
import SocksCore

/**
    An SSL Socket.
*/
public final class Socket {
    public let socket: TCPInternetSocket
    public let config: Config

    /**
         Creates a Socket from an SSL context and an
         unsecured socket's file descriptor.

         - parameter context: Re-usable SSL.Context in either Client or Server mode
         - parameter descriptor: The file descriptor from an unsecure socket already created.
    */
    public init(config: Config, socket: TCPInternetSocket) throws {
        self.config = config
        self.socket = socket
    }

    public convenience init(
        mode: Mode,
        hostname: String,
        port: UInt16 = 443,
        certificates: Certificates = .mozilla,
        verifyHost: Bool = true,
        verifyCertificates: Bool = true,
        cipher: Config.Cipher = .compat
    ) throws {
        let context = try Context(mode: mode)

        let config = try Config(
            context: context,
            certificates: certificates,
            verifyHost: verifyHost,
            verifyCertificates: verifyCertificates,
            cipher: cipher
        )

        let address = InternetAddress(hostname: hostname, port: port)
        let socket = try TCPInternetSocket(address: address)

        try self.init(config: config, socket: socket)
    }

    /**
         Connects to an SSL server from this client.

         This should only be called if the Context's mode is `.client`
    */
    public func connect(servername: String) throws {
        try socket.connect()
        let result = tls_connect_socket(
            config.context.cContext,
            socket.descriptor,
            servername
        )

        guard result == Result.OK else {
            throw TLSError.connect(config.context.error)
        }
    }

    /**
         Accepts a connection to this SSL server from a client.

         This should only be called if the Context's mode is `.server`
    */
    public func accept() throws {
        let result = tls_accept_socket(
            config.context.cContext,
            nil,
            socket.descriptor
        )

        guard result == Result.OK else {
            throw TLSError.accept(config.context.error)
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

        let result = tls_read(config.context.cContext, pointer, max)
        let bytesRead = Int(result)

        guard bytesRead >= 0 else {
            throw TLSError.receive(config.context.error)
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

        let bytesSent = tls_write(config.context.cContext, buffer.baseAddress, bytes.count)

        guard bytesSent >= 0 else {
            throw TLSError.send(config.context.error)
        }
    }

    /**
        Sends a shutdown to secure socket
    */
    public func close() throws {
        let result = tls_close(config.context.cContext)
        try socket.close()
        guard result == Result.OK else {
            throw TLSError.close(config.context.error)
        }
    }
}
