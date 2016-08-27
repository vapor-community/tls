import XCTest
import SocksCore
@testable import TLS

class LiveTests: XCTestCase {
    static var allTests = [
        ("testNoVerify", testNoVerify),
        ("testWithCACerts", testWithCACerts),
        ("testInvalidHostname", testInvalidHostname),
        ("testInvalidHostnameNoVerify", testInvalidHostnameNoVerify),
        ("testNoCerts", testNoCerts),
    ]

    func testNoVerify() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org",
            verifyCertificates: false
        )
        try socket.connect(servername: "httpbin.org")

        try socket.send("GET /\r\n\r\n".toBytes())
        let received = try socket.receive(max: 65_536).toString()
        try socket.close()

        XCTAssert(received.contains("<!DOCTYPE html>"))
    }
    
    func testWithCACerts() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org",
            certificates: Certificates.mozilla
        )

        try socket.connect(servername: "httpbin.org")

        try socket.send("GET /\r\n\r\n".toBytes())
        let received = try socket.receive(max: 65_536).toString()
        try socket.close()

        XCTAssert(received.contains("<!DOCTYPE html>"))
    }

    func testInvalidHostname() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org",
            verifyCertificates: false
        )

        do {
            try socket.connect(servername: "nothttpbin.org")
            try socket.send("GET /\r\n\r\n".toBytes())

            XCTFail("Should not have sent.")
        } catch TLSError.send(_) {

        } catch {
            XCTFail("Wrong error: \(error).")
        }
    }

    func testInvalidHostnameNoVerify() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org",
            verifyHost: false,
            verifyCertificates: false
        )

        try socket.connect(servername: "nothttpbin.org")
        try socket.send("GET /\r\n\r\n".toBytes())

        let received = try socket.receive(max: 65_536).toString()
        try socket.close()

        XCTAssert(received.contains("<!DOCTYPE html>"))
    }

    func testNoCerts() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org"
        )

        do {
            try socket.connect(servername: "nothttpbin.org")

            XCTFail("Should not have connected.")
        } catch TLSError.connect(_) {

        } catch {
            XCTFail("Wrong error: \(error).")
        }
    }
}
