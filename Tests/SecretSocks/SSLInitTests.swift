import XCTest
@testable import SecretSocks

class SSLInitTests: XCTestCase {
    static var allTests = [
        ("testExample", testExample)
    ]

    func testExample() {
        do {
            let ssl = try SSL(mode: .server, certificates: .file(
                caCertificateFile: "",
                certificateFile: "",
                privateKeyFile: "",
                signature: .selfSigned
            ))
            print(ssl)
        } catch {
            XCTFail("Initialization failed: \(error)")
        }
    }
}
