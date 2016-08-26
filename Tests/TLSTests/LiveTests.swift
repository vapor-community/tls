import XCTest
import SocksCore
@testable import TLS

class LiveTests: XCTestCase {
    static var allTests = [
        ("testLiveClientWithCACerts", testLiveClientWithCACerts)
    ]
    
    func testLiveClientWithCACerts() {

        do {
            let address = InternetAddress(hostname: "httpbin.org", port: 443)
            let rawSocket = try TCPInternetSocket(address: address)
            let descriptor = rawSocket.descriptor
            var config = Config()
            config.certificates = .certificateAuthority(signature: .signedFile(caCertificateFile: rootCertsPath()))
            let socket = try TLS.Stream(mode: .client, socket: descriptor, config: config)
            try rawSocket.connect()
            try socket.connect(servername: address.hostname)
            try socket.send("GET /\r\n\r\n".toBytes())
            let received = try socket.receive(max: 65_536)
            let str = try received.toString()
            try socket.close()
            try rawSocket.close()
            
            XCTAssert(str.contains("<!DOCTYPE html>"))
            
        } catch {
            XCTFail("Error: \(error)")
        }
    }
}

func rootCertsPath() -> String {
    return projectRootPath() + "/Certs/mozilla_certs.pem"
}

func projectRootPath() -> String {
    return #file.components(separatedBy: "/").dropLast(3).joined(separator: "/")
}
