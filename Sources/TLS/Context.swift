import CLibreSSL
import Foundation

/**
    An SSL context that contains the
    optional certificates as well as references
    to all initialized SSL libraries and configurations.

    The context is used to create secure sockets and should
    be reused when creating multiple sockets.
*/

public final class Context {
    public typealias CContext = OpaquePointer
    public let mode: Mode
    public var cContext: CContext
    
    static let initializeTlsOnce = {
        tls_init()
    }()

    /**
        Creates an SSL Context.

        - parameter mode: Client or Server.
        - parameter certificates: The certificates for the Client or Server.
    */
    public init(mode: Mode) throws {
        _ = Context.initializeTlsOnce
        
        switch mode {
        case .server:
            cContext = tls_server()
        case .client:
            cContext = tls_client()
        }

        self.mode = mode
    }

    deinit {
        tls_free(cContext)
    }

    /**
        The last error emitted using
        this context.
    */
    public var error: String {
        let string: String

        if let reason = tls_error(cContext) {
            string = String(validatingUTF8: reason) ?? "Unknown"
        } else {
            string = "Unknown"
        }
        
        return string
    }
}
