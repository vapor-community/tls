import XCTest
@testable import SSL

class SSLInitTests: XCTestCase {
    static var allTests = [
        ("testInitServer", testInitServer),
        ("testInitClient", testInitClient)
    ]

    func testInitServer() {
        do {
            _ = try SSL.Context(mode: .server, certificates: .files(
                certificateFile: "./Certs/cert.pem",
                privateKeyFile: "./Certs/key.pem",
                signature: .selfSigned
            ))
        } catch {
            XCTFail("Initialization failed: \(error)")
        }
    }

    func testInitClient() {
        do {
            _ = try SSL.Context(mode: .client, certificates: .none)
        } catch {
            XCTFail("Initialization failed: \(error)")
        }
    }
}
