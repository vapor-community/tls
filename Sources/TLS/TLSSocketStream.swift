import Async
import Bits

/// An async `UnsafeBufferPointer<UInt8>` stream wrapper for `TLSSocket`.
public final class TLSSocketStream<Socket>: ByteStream where Socket: TLSSocket {
    /// See `InputStream.Input`
    public typealias Input = ByteBuffer

    /// See `OutputStream.Output`
    public typealias Output = ByteBuffer

    /// Internal socket source stream.
    internal let source: TLSSocketSource<Socket>

    /// Internal socket sink stream.
    internal let sink: TLSSocketSink<Socket>

    /// Internal stream init. Use socket convenience method.
    internal init(socket: Socket, bufferSize: Int, on worker: Worker) {
        self.source = socket.source(on: worker, bufferSize: bufferSize)
        self.sink = socket.sink(on: worker)
    }

    /// See `InputStream.input(_:)`
    public func input(_ event: InputEvent<ByteBuffer>) {
        sink.input(event)
    }

    /// See `OutputStream.input(_:)`
    public func output<S>(to inputStream: S) where S : InputStream, Output == S.Input {
        source.output(to: inputStream)
    }
}

extension TLSSocket {
    /// Create a `TCPSocketStream` for this socket.
    public func stream(bufferSize: Int = 4096, on worker: Worker) -> TLSSocketStream<Self> {
        return TLSSocketStream(socket: self, bufferSize: bufferSize, on: worker)
    }
}
