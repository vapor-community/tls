import XCTest
import Socks
@testable import TLS
import Foundation
import Core
import Dispatch

class LiveTests: XCTestCase {
    static var allTests = [
        ("testNoVerify", testNoVerify),
        ("testWithCACerts", testWithCACerts),
        ("testInvalidHostname", testInvalidHostname),
        ("testInvalidHostnameNoVerify", testInvalidHostnameNoVerify),
        ("testSlack", testSlack),
        ("testConnectIcePay", testConnectIcePay),
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

        print(received)

        XCTAssert(received.contains("<!DOCTYPE html>"))
    }
    
    func testWithCACerts() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "httpbin.org"
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
            try socket.connect(servername: "swift.org")
            try socket.send("GET / HTTP/1.1\r\n\r\n".toBytes())

            XCTFail("Should not have sent.")
        } catch TLSError.connect(_) {
            // pass
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

    func testSlack() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "slack.com"
        )

        try socket.connect(servername: "slack.com")
        try socket.send("GET /api/rtm.start?token=xoxb-52115077872-1xDViI7osWlVEyDqwVJqj2x7 HTTP/1.1\r\nHost: slack.com\r\nAccept: application/json; charset=utf-8\r\n\r\n".toBytes())

        let received = try socket.receive(max: 65_536).toString()
        try socket.close()

        XCTAssert(received.contains("invalid_auth"))
    }
    
    func testWeixingApi() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "api.weixin.qq.com"
        )
        
        try socket.connect(servername: "api.weixin.qq.com")
        try socket.send("GET /cgi-bin/token HTTP/1.0\r\n\r\n".makeBytes())
        
        let received = try socket.receive(max: 65_536).string
        try socket.close()

        XCTAssert(received.contains("200 OK"))
    }

    func testGoogleMapsApi() throws {
        let socket = try TLS.Socket(
            mode: .client,
            hostname: "maps.googleapis.com"
        )
        
        try socket.connect(servername: "maps.googleapis.com")
        try socket.send("GET /maps/api/place/textsearch/json?query=restaurants&key=123 HTTP/1.1\r\nHost: maps.googleapis.com\r\nAccept: application/json; charset=utf-8\r\n\r\n".toBytes())
        
        let received = try socket.receive(max: 65_536).toString()
        try socket.close()
        
        XCTAssert(received.contains("REQUEST_DENIED"))
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
    
    func testServer() throws {
        let hostname = "0.0.0.0"
        
        // create 128_000 bytes of test data
        var testData:[UInt8] = []
        for _ in 1...1000 {
            testData.append(contentsOf: Array(0...255))
        }

        
        let server = try TLS.Socket(
            mode: .server,
            hostname: hostname,
            port: 0, // makes the socket bind to any available port
            certificates: .bytes(
                certificateBytes: certificate,
                keyBytes: privateKey,
                signature: Certificates.Signature.selfSigned
            ),
            verifyHost: false,
            verifyCertificates: false
        )
        
        try server.socket.bind()
        try server.socket.listen()
        
        let assignedAddress = try server.socket.localAddress()
        print("Listening on \(assignedAddress.description)")
        
        let group = DispatchGroup()
        group.enter()
        group.enter()

        background {
            do {
                try server.accept()
                var receivedData:[UInt8] = []
                while receivedData.count < testData.count {
                    let newData = try server.receive(max: 65_536)
                    receivedData.append(contentsOf: newData)
                }
                if receivedData != testData {
                    XCTFail("error")
                }
                try server.send(receivedData) // mirror data back
                try server.close()
            } catch {
                XCTFail("\(error)")
            }
            group.leave()
        }
        
        let client = try TLS.Socket(
            mode: .client,
            hostname: hostname,
            port: assignedAddress.port,
            verifyHost: false,
            verifyCertificates: false
        )

        background {
            do {
                try client.connect(servername: hostname)
                try client.send(testData)
                var receivedData:[UInt8] = []
                while receivedData.count < testData.count {
                    let newData = try client.receive(max: 65_536)
                    receivedData.append(contentsOf: newData)
                }
                if receivedData != testData {
                    XCTFail("error")
                }
            } catch {
                XCTFail("\(error)")
            }
            group.leave()
        }

        _ = group.wait(
            timeout: DispatchTime.init(secondsFromNow: 10)
        )
    }
}
