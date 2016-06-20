import COpenSSL

extension SSL {
    public static func makeMethod(for mode: Mode) throws -> Method {
        let method: Method

        switch mode {
        case .client:
            guard let m = SSLv23_client_method() else {
                throw Error.methodCreation

            }
            method = m
        case .server:
            guard let m = SSLv23_client_method() else {
                throw Error.methodCreation
            }
            method = m
        }

        return method
    }

}
