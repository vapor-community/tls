import XCTest
@testable import TLS

#if Xcode
var workDir: String {
    let parent = #file.characters.split(separator: "/").map(String.init).dropLast().joined(separator: "/")
    let path = "/\(parent)/../../"
    return path
}
#else
let workDir = "./"
#endif
class ContextTests: XCTestCase {
    static var allTests = [
        ("testInitServer", testInitServer),
        ("testInitClient", testInitClient)
    ]

    func testInitServer() {
        do {
            _ = try TLS.Context(mode: .server, certificates: .files(
                certificateFile: workDir + "Certs/cert.pem",
                privateKeyFile: workDir + "Certs/key.pem",
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
