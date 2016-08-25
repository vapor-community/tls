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
    public let certificates: Certificates
    public let mode: Mode

    /**
        Creates an SSL Context.

        - parameter mode: Client or Server.
        - parameter certificates: The certificates for the Client or Server.
    */
    public init(
        mode: Mode,
        certificates: Certificates
    ) throws {
        self.mode = mode
        self.certificates = certificates
    }
}
