import COpenSSL

public enum TLSError: Error {
    case methodCreation
    case contextCreation
    case loadCACertificate(String)
    case useCertificate(String)
    case usePrivateKey(String)
    case checkPrivateKey(String)
    case useChain(String)
    case socketCreation(String)
    case file(String)

    case accept(SocketError, String)
    case connect(SocketError, String)
    case send(SocketError, String)
    case receive(SocketError, String)
    case close(SocketError, String)
    case setTimeout(SocketError, String)

    case invalidPeerCertificate(PeerCertificateError)
}

public enum PeerCertificateError {
    case notPresented
    case noIssuerCertificate
    case invalid
}

public enum SocketError: Int32 {
    case none
    case zeroReturn
    case wantRead
    case wantWrite
    case wantConnect
    case wantAccept
    case wantX509Lookup
    case syscall
    case ssl
    case unknown

    public init(_ result: Int32) {
        switch result {
        case SSL_ERROR_NONE:
            self = .none
        case SSL_ERROR_ZERO_RETURN:
            self = .zeroReturn
        case SSL_ERROR_WANT_READ:
            self = .wantRead
        case SSL_ERROR_WANT_WRITE:
            self = .wantWrite
        case SSL_ERROR_WANT_CONNECT:
            self = .wantConnect
        case SSL_ERROR_WANT_ACCEPT:
            self = .wantAccept
        case SSL_ERROR_WANT_X509_LOOKUP:
            self = .wantX509Lookup
        case SSL_ERROR_SYSCALL:
            self = .syscall
        case SSL_ERROR_SSL:
            self = .ssl
        default:
            self = .unknown
        }
    }
}

var error: String {
    let cError = ERR_get_error()
    let string: String

    if let reason = ERR_reason_error_string(cError) {
        string = String(validatingUTF8: reason) ?? "Unknown"
    } else {
        string = "Unknown"
    }

    return string
}
