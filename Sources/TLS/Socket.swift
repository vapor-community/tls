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

    public var currSocket: TCPInternetSocket?
    public var currContext: OpaquePointer?

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
        currSocket = socket
        currContext = config.context.cContext

        guard result == Result.OK else {
            throw TLSError.connect(config.context.error)
        }
    }

    /**
         Accepts a connection to this SSL server from a client.

         This should only be called if the Context's mode is `.server`
    */
    public func accept() throws {
        let new = try socket.accept()
        let result = tls_accept_socket(
            config.context.cContext,
            &currContext,
            new.descriptor
        )
        currSocket = new

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

        let result = tls_read(currContext, pointer, max)
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
        var totalBytesSent = 0
        let buffer = UnsafeBufferPointer<UInt8>(start: bytes, count: bytes.count)
        
        while totalBytesSent < bytes.count {
            let bytesSent = tls_write(currContext, buffer.baseAddress?.advanced(by: totalBytesSent), bytes.count - totalBytesSent)
            if bytesSent <= 0 {
                throw TLSError.send(config.context.error)
            }
            totalBytesSent += bytesSent
        }
    }

    /**
        Sends a shutdown to secure socket
    */
    public func close() throws {
        let result = tls_close(currContext)
        try currSocket?.close()
        guard result == Result.OK else {
            throw TLSError.close(config.context.error)
        }
    }
}
