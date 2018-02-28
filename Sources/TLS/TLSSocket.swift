import Async
import Bits

public protocol TLSSocket {
    /// The socket's underlying descriptor.
    var descriptor: Int32 { get }

    /// If true, the TLS handshake has been completed.
    var handshakeIsComplete: Bool { get }

    /// Performs one step of the TLS handshake. May or may not result
    /// in the handshake being complete.
    func handshake() throws

    /// Reads data into the mutable byte buffer, returning status of the read.
    func read(into buffer: MutableByteBuffer) throws -> TLSSocketStatus

    /// Writes immutable data to the socket, returning status of the write.
    func write(from buffer: ByteBuffer) throws -> TLSSocketStatus

    /// Closes the socket.
    func close()
}

/// MARK: ALPN

public protocol ALPNSupporting: TLSSocket {
    var ALPNprotocols: [String] { get set }
    var selectedProtocol: String? { get }
}

/// Returned by calls to `Socket.read`
public enum TLSSocketStatus {
    /// The socket read normally.
    /// Note: count == 0 indicates the socket closed.

    case success(count: Int)
    /// The internal socket buffer is empty,
    /// this call would have blocked had this
    /// socket not been set to non-blocking mode.
    ///
    /// Use an event loop to notify you when this socket
    /// is ready to be read from again.
    ///
    /// Note: this is not an error.
    case wouldBlock
}

func ERROR(_ message: String, file: StaticString = #file, line: Int = #line) {
    print("[TLS] \(message) [\(file.description.split(separator: "/").last!):\(line)]")
}

/// For printing debug info.
func DEBUG(_ string: @autoclosure () -> String, file: StaticString = #file, line: Int = #line) {
    #if VERBOSE
    print("[VERBOSE] \(string()) [\(file.description.split(separator: "/").last!):\(line)]")
    #endif
}
