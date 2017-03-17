import CTLS

public protocol Socket: DuplexStream, InternetStream {
    var socket: TCPInternetSocket { get }
    var context: Context { get }
    var cSSL: CSSL? { get set }
    static var mode: Mode { get }
    init(_ socket: TCPInternetSocket, _ context: Context)
}

// MARK: Stream

extension Socket {
    public var isClosed: Bool {
        return socket.isClosed
    }

    public func setTimeout(_ timeout: Double) throws {
        try socket.setTimeout(timeout)
    }

    ///Sends a shutdown to secure socket
    public func close() throws {
        try socket.close()
    }
}

// MARK: ProgramStream

extension Socket {
    public var scheme: String {
        return socket.scheme
    }

    public var hostname: String {
        return socket.hostname
    }

    public var port: Port {
        return socket.port
    }

    public init(
        scheme: String,
        hostname: String,
        port: Port
    ) throws {
        try self.init(
            scheme: scheme,
            hostname: hostname,
            port: port,
            certificates: .defaults
        )
    }
}

// MARK: ReadableStream

extension Socket {
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

// MARK: Writeable Stream

extension Socket {
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

// MARK: Init

extension Socket {
    // convenience initializer
    public init(
        scheme: String,
        hostname: String,
        port: Port = 443,
        certificates: Certificates = .defaults,
        verifyHost: Bool = true,
        verifyCertificates: Bool = true,
        cipherSuite: String? = nil
    ) throws {
        let context = try Context(
            Self.mode,
            certificates,
            verifyHost: verifyHost,
            verifyCertificates: verifyCertificates,
            cipherSuite: cipherSuite
        )

        let socket = try TCPInternetSocket(
            hostname: hostname,
            port: port
        )

        self.init(
            socket,
            context
        )
    }
}
