import Async
import Dispatch
import Foundation

private let maxExcessSignalCount: Int = 2

/// Data stream wrapper for a dispatch socket.
public final class TLSSocketSource<Socket>: Async.OutputStream where Socket: TLSSocket {
    /// See OutputStream.Output
    public typealias Output = UnsafeBufferPointer<UInt8>

    /// The client stream's underlying socket.
    public var socket: Socket

    /// Bytes from the socket are read into this buffer.
    /// Views into this buffer supplied to output streams.
    private var buffer: UnsafeMutableBufferPointer<UInt8>

    /// Stores read event source.
    private var readSource: EventSource?

    /// Use a basic stream to easily implement our output stream.
    private var downstream: AnyInputStream<UnsafeBufferPointer<UInt8>>?

    /// A strong reference to the current eventloop
    private var eventLoop: EventLoop

    /// True if this source has been closed
    private var isClosed: Bool

    /// If true, downstream is ready for data.
    private var downstreamIsReady: Bool

    /// If true, the read source has been suspended
    private var sourceIsSuspended: Bool

    /// The current number of signals received while downstream was not ready
    /// since it was last ready
    private var excessSignalCount: Int

    /// If true, the source has received EOF signal.
    /// Event source should no longer be resumed. Keep reading until there is 0 return.
    private var cancelIsPending: Bool

    /// Creates a new `SocketSource`
    internal init(socket: Socket, on worker: Worker, bufferSize: Int) {
        DEBUG("TLSSocketSource.init(bufferSize: \(bufferSize))")
        self.socket = socket
        self.eventLoop = worker.eventLoop
        self.isClosed = false
        self.buffer = .init(start: .allocate(capacity: bufferSize), count: bufferSize)
        self.downstreamIsReady = true
        self.sourceIsSuspended = true
        self.cancelIsPending = false
        self.excessSignalCount = 0
        let readSource = self.eventLoop.onReadable(descriptor: socket.descriptor, readSourceSignal)
        self.readSource = readSource
    }

    /// See OutputStream.output
    public func output<S>(to inputStream: S) where S: Async.InputStream, S.Input == UnsafeBufferPointer<UInt8> {
        DEBUG("TLSSocketSource.output<\(S.self)>(to: \(inputStream))")
        downstream = AnyInputStream(inputStream)
        resumeIfSuspended()
    }

    /// Cancels reading
    public func close() {
        DEBUG("TLSSocketSource.close()")
        guard !isClosed else {
            return
        }
        guard let readSource = self.readSource else {
            ERROR("SocketSource readSource illegally nil during close.")
            return
        }
        readSource.cancel()
        socket.close()
        downstream?.close()
        self.readSource = nil
        downstream = nil
        isClosed = true
    }

    /// Reads data and outputs to the output stream
    /// important: the socket _must_ be ready to read data
    /// as indicated by a read source.
    private func readData() {
        DEBUG("TLSSocketSource.readData()")
        guard let downstream = self.downstream else {
            ERROR("Unexpected nil downstream on SocketSource during readData.")
            return
        }

        do {
            let read = try socket.read(into: buffer)
            DEBUG("TLSSocketSource.socket.read() -> \(read)")
            switch read {
            case .success(let count):
                guard count > 0 else {
                    close()
                    return
                }

                let view = UnsafeBufferPointer<UInt8>(start: buffer.baseAddress, count: count)
                DEBUG("TLSSocketSource.view = \(String(bytes: view, encoding: .ascii) ?? "nil")")
                downstreamIsReady = false
                let promise = Promise(Void.self)
                downstream.input(.next(view, promise))
                promise.future.addAwaiter { result in
                    DEBUG("TLSSocketSource.downstream.input.future.complete(\(result)) [cancelIsPending: \(self.cancelIsPending)]")
                    switch result {
                    case .error(let e): downstream.error(e)
                    case .expectation: self.readData()
                    }
                }
            case .wouldBlock:
                resumeIfSuspended()
            }
        } catch {
            // any errors that occur here cannot be thrown,
            // so send them to stream error catcher.
            downstream.error(error)
        }
    }

    /// Called when the read source signals.
    private func readSourceSignal(isCancelled: Bool) {
        DEBUG("TLSSocketSource.readSourceSignal(\(isCancelled))")
        guard !isCancelled else {
            // source is cancelled, we will never receive signals again
            cancelIsPending = true
            if downstreamIsReady {
                readData()
            }
            return
        }

        if !socket.handshakeIsComplete {
            do {
                try socket.handshake()
            } catch {
                ERROR("\(error)")
            }
            return
        }

        guard downstreamIsReady else {
            // downstream is not ready for data yet
            excessSignalCount = excessSignalCount &+ 1
            if excessSignalCount >= maxExcessSignalCount {
                guard let readSource = self.readSource else {
                    ERROR("TLSSocketSource readSource illegally nil during signal.")
                    return
                }
                DEBUG("TLSSocketSource.suspend()")
                readSource.suspend()
                sourceIsSuspended = true
            }
            return
        }

        // downstream ready, reset exces count
        excessSignalCount = 0
        readData()
    }

    /// Resumes the readSource if it was currently suspended.
    private func resumeIfSuspended() {
        DEBUG("TLSSocketSource.resumeIfSuspended() [sourceIsSuspended: \(sourceIsSuspended)]")
        guard sourceIsSuspended else {
            return
        }

        guard let readSource = self.readSource else {
            ERROR("SocketSource readSource illegally nil on resumeIfSuspended.")
            return
        }
        sourceIsSuspended = false
        readSource.resume()
    }

    /// Deallocated the pointer buffer
    deinit {
        buffer.baseAddress?.deallocate()
    }
}

/// MARK: Create

extension TLSSocket {
    /// Creates a data stream for this socket on the supplied event loop.
    public func source(on eventLoop: Worker, bufferSize: Int = 4096) -> TLSSocketSource<Self> {
        return .init(socket: self, on: eventLoop, bufferSize: bufferSize)
    }
}


