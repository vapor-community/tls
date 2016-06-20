import COpenSSL

public final class SSL {
    public typealias Method = UnsafePointer<SSL_METHOD>

    public var method: Method
    public var context: Context
    static let verifyDepth = 2

    init(
        mode: Mode,
        certificates: Certificates,
        cipherList: String = "ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL"
    ) throws {
        SSL_library_init()
        SSL_load_error_strings()
        OPENSSL_config(nil)
        OPENSSL_add_all_algorithms_conf()

        let method = try SSL.makeMethod(for: mode)
        self.method = method

        let context = try Context(
            method: method,
            mode: mode,
            certificates: certificates,
            cipherList: cipherList,
            verify: certificates.areSelfSigned ? .none : .peer,
            verifyDepth: SSL.verifyDepth
        )
        self.context = context
    }
}
