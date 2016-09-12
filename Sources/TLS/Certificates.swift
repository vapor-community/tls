import Core

public enum Certificates {
    public enum Signature {
        case selfSigned
        case signedFile(caCertificateFile: String)
        case signedDirectory(caCertificateDirectory: String)
        case signedBytes(caCertificateBytes: Bytes)

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
    case bytes(certificateBytes: Bytes, keyBytes: Bytes, signature: Signature)

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
        case .bytes(certificateBytes: _, keyBytes: _, signature: let signature):
            return signature.isSelfSigned
        }
    }
}

extension Certificates {
    public static var mozilla: Certificates {
        let root = #file.characters
            .split(separator: "/", omittingEmptySubsequences: false)
            .dropLast(3)
            .map { String($0) }
            .joined(separator: "/")

        do {
            print("Debug loading: \(root + "/Certs/mozilla_certs.pem")")
            let bytes = try DataFile().load(path: root + "/Certs/mozilla_certs.pem")
            print("Start bytes")
            print(bytes)
            print("End bytes")
        } catch {
            print("Load failed: \(error)")
        }

        return .certificateAuthority(
            signature: .signedFile(
                caCertificateFile: root + "/Certs/mozilla_certs.pem"
            )
        )
    }
}
