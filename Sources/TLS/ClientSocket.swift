import CTLS

/// An SSL Socket.
public protocol ClientSocket: Socket, ClientStream { }

extension ClientSocket {
    /// Convenience connect w/o servername
    public func connect() throws {
        try connect(servername: nil)
    }

    /// Connects to an SSL server from this client.
    ///
    /// This should only be called if the Context's mode is `.client`
    public func connect(servername: String?) throws {
        try socket.connect()

        guard let ssl = SSL_new(context.cContext) else {
            throw makeError(functionName: "SSL_new")
        }
        cSSL = ssl

        try assert(
            SSL_set_fd(ssl, socket.descriptor.raw),
            functionName: "SSL_set_fd"
        )

        if context.verifyHost {
            print("Warning: Host verification not implemented.")
            //            let param = SSL_get0_param(ssl)
            //            X509_VERIFY_PARAM_set_hostflags(
            //                param,
            //                UInt32(X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS)
            //            )
            //            X509_VERIFY_PARAM_set1_host(param, servername, 0);
            //            SSL_set_verify(ssl, SSL_VERIFY_PEER, nil)
        }

        try assert(
            SSL_connect(ssl),
            functionName: "SSL_connect"
        )
        
        try assert(
            SSL_do_handshake(ssl),
            functionName: "SSL_do_handshake"
        )
    }
}
