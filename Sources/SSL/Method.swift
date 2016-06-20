import COpenSSL

/**
    An SSL method of communication based on the Client or Server mode.
*/
public class Method {
    public typealias CMethod = UnsafePointer<SSL_METHOD>

    public let cMethod: CMethod

    /**
        Creates a Method from a Mode.

        Calls `TLS_server_method` or `TLS_client_method` internally.
    */
    public init(mode: Mode) throws {
        let method: CMethod

        switch mode {
        case .client:
            guard let m = SSLv23_client_method() else {
                throw Error.methodCreation

            }
            method = m
        case .server:
            guard let m = SSLv23_server_method() else {
                throw Error.methodCreation
            }
            method = m
        }

        cMethod = method
    }
}
