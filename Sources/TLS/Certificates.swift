public enum Certificates {
    public enum Signature {
        case selfSigned
        case signedFile(caCertificateFile: String)
        case signedDirectory(caCertificateDirectory: String)

        public var isSelfSigned: Bool {
            switch self {
            case .selfSigned:
                return true
            default:
                return false
            }
        }
    }

    case none
    case files(certificateFile: String, privateKeyFile: String, signature: Signature)
    case chain(chainFile: String, signature: Signature)
    case certificateAuthority(signature: Signature)

    public var areSelfSigned: Bool {
        switch self {
        case .none:
            return true
        case .files(_, _, let signature):
            return signature.isSelfSigned
        case .chain(_, let signature):
            return signature.isSelfSigned
        case .certificateAuthority(let signature):
            return signature.isSelfSigned
        }
    }
}
