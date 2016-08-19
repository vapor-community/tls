import XCTest
@testable import TLS

class ContextTests: XCTestCase {
    static var allTests = [
        ("testInitServer", testInitServer),
        ("testInitClient", testInitClient)
    ]

    func testInitServer() {
        do {
            _ = try TLS.Context(mode: .server, certificates: .files(
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
            _ = try TLS.Context(mode: .client, certificates: .none)
        } catch {
            XCTFail("Initialization failed: \(error)")
        }
    }
}
