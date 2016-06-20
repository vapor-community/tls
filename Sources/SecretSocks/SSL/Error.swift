import COpenSSL

extension SSL {
    public enum Error: ErrorProtocol {
        case methodCreation
        case contextCreation
        case loadCACertificate(String)
        case useCertificate(String)
        case usePrivateKey(String)
        case checkPrivateKey(String)
        case useChain(String)
        case socketCreation(String)
        case accept(String)
        case connect(String)
        case send(String)
        case receive(String)
    }

    static var error: String {
        let cError = ERR_get_error()
        let string: String

        if let reason = ERR_reason_error_string(cError) {
            string = String(validatingUTF8: reason) ?? "Unknown"
        } else {
            string = "Unknown"
        }

        return string
    }
}
