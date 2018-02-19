import Async
import COpenSSL
import TCP
import TLS

/// A TLS client implemented by COpenSSL.
public final class OpenSSLClient: TLSClient {
    /// The TLS socket.
    public let socket: OpenSSLSocket

    /// See TLSClient.settings
    public var settings: TLSClientSettings

    /// Underlying TCP client.
    private let tcp: TCPClient

    /// Create a new `OpenSSLClient`
    public init(
        tcp: TCPClient,
        using settings: TLSClientSettings,
        configuration: OpenSSLSettings = OpenSSLSettings()
    ) throws {
        let socket = try OpenSSLSocket(tcp: tcp.socket, method: .ssl23, side: .client, settings: configuration)
        self.settings = settings
        self.socket = socket
        self.tcp = tcp
    }

    /// See TLSClient.connect
    public func connect(hostname: String, port: UInt16) throws {
        var hostname = hostname
        try tcp.connect(hostname: hostname, port: port)
        SSL_ctrl(socket.cSSL, SSL_CTRL_SET_TLSEXT_HOSTNAME, Int(TLSEXT_NAMETYPE_host_name), &hostname)
        SSL_connect(socket.cSSL)
    }

    /// See TLSClient.close
    public func close() {
        socket.close()
        tcp.close()
    }
}
