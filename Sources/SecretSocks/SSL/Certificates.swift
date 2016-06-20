extension SSL {
    public enum Certificates {
        public enum Signature {
            case selfSigned
            case signed

            public var isSelfSigned: Bool {
                switch self {
                case .selfSigned:
                    return true
                case .signed:
                    return false
                }
            }
        }

        case file(caCertificateFile: String, certificateFile: String, privateKeyFile: String, signature: Signature)
        case directory(caCertificateDirectory: String, certificateFile: String, privateKeyFile: String, signature: Signature)
        case chain(chainFile: String, signature: Signature)

        public var areSelfSigned: Bool {
            switch self {
            case .file(_, _, _, let signature):
                return signature.isSelfSigned
            case .directory(_, _, _, let signature):
                return signature.isSelfSigned
            case .chain(_, let signature):
                return signature.isSelfSigned
            }
        }
    }
}
