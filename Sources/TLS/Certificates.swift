import Core
import libc

/// Certificates and signatures used
/// for securing TLS connections
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

    public static var defaults: Certificates {
		if let system = system { return system }
		if let openbsd = openbsd { return openbsd }
		fatalError("No system certificates found")
    }
}

extension Certificates {
    public static var openbsd: Certificates? {
        let root = #file.toCharacterSequence()
            .split(separator: "/", omittingEmptySubsequences: false)
            .dropLast(3)
            .map { String($0) }
            .joined(separator: "/")
		
		let filePath = root + "/Certs/openbsd_certs.pem"
		guard fileExists(filePath) else { return nil }

        return .certificateAuthority(
            signature: .signedFile(
                caCertificateFile: filePath
            )
        )
    }
    
    static var system: Certificates? {
        let paths = [
            "/etc/ssl/cert.pem",                  // OSX OpenSSL
            "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
            "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
            "/etc/ssl/ca-bundle.pem",             // OpenSUSE
            "/etc/pki/tls/cacert.pem",            // OpenELEC
            "/etc/ssl/certs",                     // SLES10/SLES11, https://golang.org/issue/12139
            "/system/etc/security/cacerts"        // Android
        ]

        return paths.flatMap { (path: String) -> Certificates? in
            guard fileExists(path) else {
                return nil
            }
            
            return .certificateAuthority(
                signature: .signedFile(
                    caCertificateFile: path
                )
            )
        }.first
    }
}

fileprivate func fileExists(_ path: String) -> Bool {
    return path.utf8CString.withUnsafeBufferPointer {
        guard let baseAddress = $0.baseAddress else {
            return false
        }
        
        return access(baseAddress, R_OK) == 0
    }
}

extension String {
    #if swift(>=4.0)
    internal func toCharacterSequence() -> String {
        return self
    }
    #else
    internal func toCharacterSequence() -> CharacterView {
        return self.characters
    }
    #endif  
}
