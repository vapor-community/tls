import COpenSSL

/**
    An SSL Socket.
*/
public final class Socket {
    public typealias CSSL = UnsafeMutablePointer<ssl_st>

    public let cSSL: CSSL
    public let context: Context
    public let descriptor: Int32

    /**
        Indicates whether or not an ssl connection received a shutdown.
    */
    public var closed: Bool {
        let shutDown = SSL_get_shutdown(cSSL)
        switch shutDown {
        case 0:
            return false
        case SSL_SENT_SHUTDOWN, SSL_RECEIVED_SHUTDOWN:
            return true
        default:
            return true
        }
    }

    /**
         The current timeout associated with the socket.
    */
    public var timeout: Int {
        let session = SSL_get_session(cSSL)
        return SSL_SESSION_get_time(session)
    }

    /**
         Creates a Socket from an SSL context and an
         unsecured socket's file descriptor.

         - parameter context: Re-usable SSL.Context in either Client or Server mode
         - parameter descriptor: The file descriptor from an unsecure socket already created.
    */
    public init(context: Context, descriptor: Int32) throws {
        guard let ssl = SSL_new(context.cContext) else {
            throw TLSError.socketCreation(error)
        }

        SSL_set_fd(ssl, descriptor)
        self.context = context
        self.cSSL = ssl
        self.descriptor = descriptor
    }

    deinit {
        SSL_shutdown(cSSL)
        SSL_free(cSSL)
    }


    /**
        Set a timeout for a given connection, in Seconds.
    */
    public func setTimeout(_ timeout: Int) throws {
        let session = SSL_get_session(cSSL)
        let result = SSL_SESSION_set_time(session, timeout)
        guard result != -1 else { throw TLSError.setTimeout(SocketError(Int32(result)), error) }
    }

    /**
         Connects to an SSL server from this client.

         This should only be called if the Context's mode is `.client`
    */
    public func connect() throws {
        let result = SSL_connect(cSSL)
        guard result == Result.OK else {
            throw TLSError.connect(SocketError(result), error)
        }
    }

    /**
         Accepts a connection to this SSL server from a client.

         This should only be called if the Context's mode is `.server`
    */
    public func accept() throws {
        let result = SSL_accept(cSSL)
        guard result == Result.OK else {
            throw TLSError.accept(SocketError(result), error)
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

        let result = SSL_read(cSSL, pointer, max.int32)
        let bytesRead = Int(result)

        guard bytesRead >= 0 else {
            throw TLSError.receive(SocketError(result), error)
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

        let bytesSent = SSL_write(cSSL, buffer.baseAddress, bytes.count.int32)

        guard bytesSent >= 0 else {
            throw TLSError.send(SocketError(bytesSent), error)
        }
    }

    /**
        Sends a shutdown to secure socket
    */
    public func close() throws {
        let result = SSL_shutdown(cSSL)
        guard result != -1 else { throw TLSError.close(SocketError(result), error) }
    }

    /**
         Verifies the connection with the peer.

         - throws: TLSError.invalidPeerCertificate(PeerCertificateError)
    */
    public func verifyConnection() throws {
        if
            case.server = context.mode,
            context.certificates.areSelfSigned
        {
            return
        }

        guard let certificate = SSL_get_peer_certificate(cSSL) else {
            throw TLSError.invalidPeerCertificate(.notPresented)
        }
        defer {
            X509_free(certificate)
        }

        let result = SSL_get_verify_result(cSSL).int32
        switch result {
        case X509_V_OK:
            break
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            if !context.certificates.areSelfSigned {
                throw TLSError.invalidPeerCertificate(.noIssuerCertificate)
            }
        default:
            throw TLSError.invalidPeerCertificate(.invalid)
        }
    }
}
