import XCTest
import Sockets
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
        ("testWeixingApi", testWeixingApi),
        ("testGoogleMapsApi", testGoogleMapsApi),
        ("testConnectIcePay", testConnectIcePay),
        ("testServer", testServer),
    ]

    func testNoVerify() throws {
        let socket = try InternetSocket(
            .client,
            hostname: "swift.org",
            verifyCertificates: false
        )
        try socket.connect(servername: "swift.org")
        try socket.write("GET / HTTP/1.1\r\nHost: swift.org\r\n\r\n".makeBytes())
        let received = try socket.read(max: 65_536).makeString()
        try socket.close()

        XCTAssert(received.contains("200 OK"))
    }
    
    func testWithCACerts() throws {
        let socket = try InternetSocket(
            .client,
            hostname: "swift.org"
        )

        try socket.connect(servername: "swift.org")

        try socket.write("GET / HTTP/1.1\r\nHost: swift.org\r\n\r\n".makeBytes())
        let received = try socket.read(max: 65_536).makeString()
        try socket.close()

        XCTAssert(received.contains("200 OK"))
    }

    func testInvalidHostname() throws {
        let socket = try InternetSocket(
            .client,
            hostname: "swift.org",
            verifyCertificates: false
        )

        do {
            try socket.connect(servername: "httpbin.org")
            try socket.write("GET / HTTP/1.1\r\nHost: swift.org\r\n\r\n".makeBytes())

            print("Warning: not checking for invalid host name")
            // XCTFail("Should not have sent.")
        } catch let error as TLSError {
            if error.functionName == "SSL_connect" && error.reason == "certificate verify failed" {
                // pass
            } else {
                XCTFail("Wrong error: \(error)")
            }
        }
    }

    func testInvalidHostnameNoVerify() throws {
        let socket = try InternetSocket(
            .client,
            hostname: "swift.org",
            verifyHost: false,
            verifyCertificates: false
        )

        try socket.connect(servername: "nothttpbin.org")
        try socket.write("GET / HTTP/1.1\r\nHost: swift.org\r\n\r\n".makeBytes())

        let received = try socket.read(max: 65_536).makeString()
        try socket.close()

        XCTAssert(received.contains("200 OK"))
    }

    func testSlack() throws {
        let socket = try InternetSocket(
            .client,
            hostname: "slack.com"
        )

        try socket.connect(servername: "slack.com")
        try socket.write("GET /api/rtm.start?token=xoxb-52115077872-1xDViI7osWlVEyDqwVJqj2x7 HTTP/1.1\r\nHost: slack.com\r\nAccept: application/json; charset=utf-8\r\n\r\n".makeBytes())

        let received = try socket.read(max: 65_536).makeString()
        try socket.close()

        XCTAssert(received.contains("invalid_auth"))
    }
    
    func testWeixingApi() throws {
        let socket = try InternetSocket(
            .client,
            hostname: "api.weixin.qq.com"
        )
        
        try socket.connect(servername: "api.weixin.qq.com")
        try socket.write("GET /cgi-bin/token HTTP/1.0\r\n\r\n".makeBytes())
        
        let received = try socket.read(max: 65_536).makeString()
        try socket.close()

        XCTAssert(received.contains("200 OK"))
    }

    func testGoogleMapsApi() throws {
        let socket = try InternetSocket(
            .client,
            hostname: "maps.googleapis.com",
            port: 443
        )
        
        try socket.connect(servername: "maps.googleapis.com")
        try socket.write("GET /maps/api/place/textsearch/json?query=restaurants&key=123 HTTP/1.1\r\nHost: maps.googleapis.com\r\nAccept: application/json; charset=utf-8\r\n\r\n".makeBytes())
        
        let received = try socket.read(max: 65_536).makeString()
        try socket.close()
        
        XCTAssert(received.contains("REQUEST_DENIED"))
    }

    func testConnectIcePay() throws {
        do {
            let stream = try InternetSocket(
                .client,
                hostname: "connect.icepay.com",
                port: 443
            )
            try stream.connect(servername: "connect.icepay.com")
            try stream.write("GET /plaintext HTTP/1.1".makeBytes())
            try stream.write("\r\n".makeBytes())
            try stream.write("Accept: */*".makeBytes())
            try stream.write("\r\n".makeBytes())
            try stream.write("Host: connect.icepay.com".makeBytes())
            try stream.write("\r\n\r\n".makeBytes()) // double line terminator

            let result = try stream.read(max: 2048).makeString()
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

        
        let server = try InternetSocket(
            .server,
            hostname: hostname,
            port: 8203,
            certificates: .bytes(
                certificateBytes: certificate,
                keyBytes: privateKey,
                signature: Certificates.Signature.selfSigned
            ),
            verifyHost: false,
            verifyCertificates: false
        )
        
        try server.socket.bind()
        try server.socket.listen(max: 4096)
        
        let group = DispatchGroup()
        group.enter()
        group.enter()

        background {
            do {
                let client = try server.accept()
                var receivedData:[UInt8] = []
                while receivedData.count < testData.count {
                    let newData = try client.read(max: 65_536)
                    receivedData.append(contentsOf: newData)
                }
                if receivedData != testData {
                    XCTFail("error")
                }
                try client.write(receivedData) // mirror data back
                try client.close()
            } catch {
                XCTFail("\(error)")
            }
            group.leave()
        }
        
        let client = try InternetSocket(
            .client,
            hostname: hostname,
            port: 8203,
            verifyHost: false,
            verifyCertificates: false
        )

        background {
            do {
                try client.connect(servername: hostname)
                try client.write(testData)
                var receivedData:[UInt8] = []
                while receivedData.count < testData.count {
                    let newData = try client.read(max: 65_536)
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
