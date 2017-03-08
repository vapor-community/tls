import CTLS

public struct TLSError: Error {
    public let functionName: String
    public let returnCode: Int32?
    public let reason: String

    public init(
        functionName: String,
        returnCode: Int32?,
        reason: String
    ) {
        self.functionName = functionName
        self.returnCode = returnCode
        self.reason = reason
    }
}

// MARK: Convenience

extension Socket {
    func assert(
        _ returnCode: Int32,
        functionName: String
    ) throws {
        if returnCode != 1 {
            throw makeError(
                functionName: functionName,
                returnCode: returnCode
            )
        }
    }

    func makeError(
        functionName: String,
        returnCode: Int32? = nil
    ) -> TLSError {
        let reason: String?

        if let cSSL = cSSL, let returnCode = returnCode {
            let res = SSL_get_error(cSSL, returnCode)
            switch res {
            case SSL_ERROR_ZERO_RETURN:
                reason = "The TLS/SSL connection has been closed."
            case
            SSL_ERROR_WANT_READ,
            SSL_ERROR_WANT_WRITE,
            SSL_ERROR_WANT_CONNECT,
            SSL_ERROR_WANT_ACCEPT:
                reason = "The operation did not complete; the same TLS/SSL I/O function should be called again later."
            case SSL_ERROR_WANT_X509_LOOKUP:
                reason = "The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again."
            case SSL_ERROR_SYSCALL:
                reason = String(validatingUTF8: strerror(errno)) ?? "System call error"
            default:
                reason = "A failure in the SSL library occurred."
            }
        } else {
            reason = nil
        }

        return context.makeError(
            functionName: functionName,
            returnCode: returnCode,
            reason: reason
        )
    }
}

extension Context {
    private var errorReason: String? {
        let err = ERR_get_error()
        if err == 0 {
            return nil
        }

        if let errorStr = ERR_reason_error_string(err) {
            return String(validatingUTF8: errorStr)
        } else {
            return nil
        }
    }

    func assert(
        _ returnCode: Int32,
        functionName: String,
        reason: String? = nil
    ) throws {
        if returnCode != 1 {
            throw makeError(
                functionName: functionName,
                returnCode: returnCode,
                reason: reason
            )
        }
    }

    func makeError(
        functionName: String,
        returnCode: Int32? = nil,
        reason otherReason: String? = nil
    ) -> TLSError {
        let reason: String

        if let error = errorReason {
            reason = error
        } else if let otherReason = otherReason {
            reason = otherReason
        } else {
            reason = "Unknown"
        }

        return TLSError(
            functionName: functionName,
            returnCode: returnCode,
            reason: reason
        )
    }
}

// MARK: Debuggable
import Debugging

extension TLSError: Debuggable {
    public static var readableName: String {
        return "Transport Layer Security Error"
    }

    public var identifier: String {
        if let returnCode = returnCode {
            return "\(functionName) (\(returnCode))"
        } else {
            return functionName
        }
    }

    public var possibleCauses: [String] {
        return []
    }

    public var suggestedFixes: [String] {
        return []
    }
}
