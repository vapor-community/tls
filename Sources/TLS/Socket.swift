import CTLS

public protocol Socket: Stream {
    var socket: TCPInternetSocket { get }
    var context: Context { get }
    var cSSL: CSSL? { get set }
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
}

// MARK: Init

extension Socket {
    // convenience initializer
    public init(
        _ mode: Mode,
        scheme: String = "https",
        hostname: String = "0.0.0.0",
        port: Port = 443,
        certificates: Certificates = .defaults,
        verifyHost: Bool = true,
        verifyCertificates: Bool = true,
        cipherSuite: String? = nil
    ) throws {
        let context = try Context(
            mode,
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
