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

        if let servername = servername, context.verifyHost {
            #if ENABLE_HOSTNAME_VERIFICATION
            let param = SSL_get0_param(ssl)
            X509_VERIFY_PARAM_set_hostflags(
                param,
                UInt32(X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS)
            )
            X509_VERIFY_PARAM_set1_host(param, servername, 0);
            SSL_set_verify(ssl, SSL_VERIFY_PEER, nil)
            #endif
        }

        /// https://github.com/vapor/tls/issues/47
        if let servername = servername {
            var cName = servername.utf8CString
            cName.withUnsafeMutableBytes { name in
                // SSL_set_tlsext_host_name is a C macro,
                // which is not directly callable in Swift.
                // This is its expanded form.
                _ = SSL_ctrl(ssl,
                             SSL_CTRL_SET_TLSEXT_HOSTNAME,
                             Int(TLSEXT_NAMETYPE_host_name),
                             name.baseAddress)
            }
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
