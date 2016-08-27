import TLS

extension Certificates {
    static var mozilla: Certificates {
        let root = #file.components(separatedBy: "/").dropLast(3).joined(separator: "/")
        return .certificateAuthority(
            signature: .signedFile(
                caCertificateFile: root + "/Certs/mozilla_certs.pem"
            )
        )
    }
}
