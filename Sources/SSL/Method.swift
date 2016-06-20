import COpenSSL

public class Method {
    public typealias CMethod = UnsafePointer<SSL_METHOD>

    public let cMethod: CMethod

    public init(mode: Mode) throws {
        let method: CMethod

        switch mode {
        case .client:
            guard let m = SSLv23_client_method() else {
                throw Error.methodCreation

            }
            method = m
        case .server:
            guard let m = SSLv23_method() else {
                throw Error.methodCreation
            }
            method = m
        }

        cMethod = method
    }
}
