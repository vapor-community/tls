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
        ("testSlack", testSlack),
        ("testConnectIcePay", testConnectIcePay),
        ("testConnectSMTP", testConnectSMTP),
    ]

    func testNoVerify() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org",
            verifyCertificates: false
        )
        try socket.connect(servername: "httpbin.org")

        try socket.send("GET / HTTP/1.0\r\n\r\n".toBytes())
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

        try socket.send("GET / HTTP/1.0\r\n\r\n".toBytes())
        let received = try socket.receive(max: 65_536).toString()
        try socket.close()

        XCTAssert(received.contains("httpbin(1): HTTP Client Testing Service"))
    }

    func testInvalidHostname() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org",
            verifyCertificates: false
        )

        do {
            try socket.connect(servername: "nothttpbin.org")
            try socket.send("GET / HTTP/1.1\r\n\r\n".toBytes())

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
        try socket.send("GET / HTTP/1.0\r\n\r\n".toBytes())

        let received = try socket.receive(max: 65_536).toString()
        try socket.close()

        XCTAssert(received.contains("<!DOCTYPE html>"))
    }

    func testNoCerts() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org",
            certificates: .none
        )

        do {
            try socket.connect(servername: "nothttpbin.org")

            XCTFail("Should not have connected.")
        } catch TLSError.connect(_) {

        } catch {
            XCTFail("Wrong error: \(error).")
        }
    }

    func testSlack() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "slack.com",
            certificates: Certificates.mozilla
        )

        try socket.connect(servername: "slack.com")
        try socket.send("GET /api/rtm.start?token=xoxb-52115077872-1xDViI7osWlVEyDqwVJqj2x7 HTTP/1.1\r\nHost: slack.com\r\nAccept: application/json; charset=utf-8\r\n\r\n".toBytes())

        let received = try socket.receive(max: 65_536).toString()
        try socket.close()

        XCTAssert(received.contains("invalid_auth"))
    }

    func testConnectIcePay() throws {
        do {
            let stream = try TLS.Socket(mode: .client, hostname: "connect.icepay.com")
            try stream.connect(servername: "connect.icepay.com")
            try stream.send("GET /plaintext HTTP/1.1".toBytes())
            try stream.send("\r\n".toBytes())
            try stream.send("Accept: */*".toBytes())
            try stream.send("\r\n".toBytes())
            try stream.send("Host: connect.icepay.com".toBytes())
            try stream.send("\r\n\r\n".toBytes()) // double line terminator

            let result = try stream.receive(max: 2048).toString()
            XCTAssert(result.contains("404"))
        } catch {
            XCTFail("SSL Connection Failed: \(error)")
        }
    }

    func testConnectSMTP() {
        do {
            let stream = try TLS.Socket(mode: .client, hostname: "smtp.sendgrid.net", port: 465)
            try stream.connect(servername: "smtp.sendgrid.net")
            // SMTP Server initiates w/ greeting. Receive first here is proper
            let receive = try stream.receive(max: 2048).toString()
            XCTAssert(receive.hasPrefix("220"))
        } catch TLSError.receive(_) {
            XCTFail("SMTP TLS Connection Failed")
        } catch { }
    }
}
