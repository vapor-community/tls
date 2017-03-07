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
        ("testNoCerts", testNoCerts),
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
            try socket.connect(servername: "nothttpbin.org")
            try socket.send("GET / HTTP/1.1\r\n\r\n".toBytes())

            XCTFail("Should not have sent.")
        } catch TLSError.handshake(_) {

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
            // on Linux, the TLS setup breaks
        } catch TLSError.handshake(_) {
            // on OSX, SNI throws a handshake error: "name 'nothttpbin.org' not present in server certificate"
        } catch {
            XCTFail("Wrong error: \(error).")
        }
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
        
        // private key
        let privateKey:[UInt8] = [45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 73, 73, 67, 100, 119, 73, 66, 65, 68, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 83, 67, 65, 109, 69, 119, 103, 103, 74, 100, 65, 103, 69, 65, 65, 111, 71, 66, 65, 78, 77, 72, 83, 51, 83, 112, 78, 50, 77, 66, 67, 109, 114, 79, 10, 90, 106, 53, 118, 102, 57, 82, 65, 78, 69, 120, 98, 103, 87, 69, 86, 66, 79, 105, 103, 56, 90, 73, 84, 87, 83, 81, 107, 105, 86, 75, 47, 98, 106, 120, 99, 108, 122, 71, 77, 57, 88, 101, 50, 79, 107, 72, 118, 108, 83, 82, 79, 102, 88, 101, 51, 111, 80, 89, 102, 106, 119, 49, 102, 10, 122, 98, 84, 100, 65, 49, 113, 106, 120, 121, 43, 77, 56, 117, 76, 98, 105, 49, 71, 80, 89, 84, 103, 107, 78, 119, 105, 68, 74, 56, 84, 90, 112, 121, 106, 101, 73, 54, 74, 90, 105, 79, 98, 89, 117, 113, 51, 119, 115, 48, 79, 81, 99, 77, 82, 70, 103, 66, 119, 107, 88, 57, 49, 73, 10, 103, 90, 48, 47, 71, 79, 121, 103, 80, 47, 118, 70, 50, 107, 109, 74, 53, 89, 104, 69, 54, 105, 50, 53, 69, 97, 43, 49, 65, 103, 77, 66, 65, 65, 69, 67, 103, 89, 69, 65, 117, 73, 112, 49, 105, 117, 82, 55, 119, 103, 70, 106, 43, 98, 106, 98, 73, 112, 104, 103, 52, 100, 122, 118, 10, 110, 121, 75, 97, 82, 113, 113, 90, 54, 49, 68, 114, 84, 56, 72, 74, 118, 49, 105, 81, 71, 105, 79, 55, 111, 57, 43, 89, 102, 69, 86, 51, 86, 54, 79, 115, 50, 73, 74, 75, 71, 48, 68, 107, 97, 97, 47, 85, 101, 56, 100, 110, 85, 116, 118, 72, 121, 80, 86, 74, 101, 118, 55, 77, 10, 87, 104, 70, 54, 65, 52, 85, 56, 98, 73, 73, 43, 115, 78, 106, 99, 106, 66, 84, 80, 82, 74, 74, 65, 49, 84, 106, 90, 83, 119, 102, 106, 79, 99, 98, 109, 120, 49, 115, 47, 118, 99, 88, 108, 53, 76, 111, 47, 76, 112, 50, 102, 54, 105, 110, 69, 53, 87, 118, 117, 103, 88, 97, 81, 10, 84, 102, 103, 117, 56, 112, 84, 88, 106, 110, 76, 78, 111, 73, 43, 99, 121, 55, 85, 67, 81, 81, 68, 47, 104, 51, 47, 81, 76, 103, 78, 66, 53, 109, 108, 65, 88, 113, 79, 74, 76, 100, 54, 86, 98, 99, 77, 67, 77, 107, 106, 107, 48, 48, 50, 100, 75, 99, 116, 111, 79, 49, 47, 84, 10, 106, 76, 113, 70, 84, 107, 90, 116, 54, 56, 107, 70, 88, 85, 114, 113, 98, 118, 81, 89, 107, 53, 57, 77, 52, 51, 109, 100, 53, 90, 53, 89, 83, 119, 69, 114, 66, 71, 75, 54, 102, 68, 74, 68, 65, 107, 69, 65, 48, 50, 114, 80, 89, 115, 85, 56, 79, 109, 55, 120, 121, 120, 74, 88, 10, 57, 121, 57, 117, 102, 83, 73, 112, 53, 77, 76, 120, 121, 103, 81, 122, 56, 90, 54, 111, 110, 83, 90, 107, 74, 104, 82, 80, 101, 101, 120, 87, 83, 114, 120, 65, 66, 71, 113, 101, 103, 111, 73, 47, 70, 102, 76, 120, 109, 84, 74, 57, 112, 72, 75, 73, 83, 109, 113, 89, 50, 100, 68, 87, 10, 87, 83, 65, 105, 112, 119, 74, 65, 82, 114, 53, 99, 120, 71, 88, 52, 119, 79, 88, 112, 102, 99, 105, 49, 118, 101, 84, 86, 71, 115, 109, 111, 107, 53, 77, 89, 87, 48, 71, 107, 50, 122, 52, 87, 56, 109, 82, 57, 119, 122, 80, 83, 55, 57, 85, 98, 54, 112, 75, 56, 116, 74, 57, 47, 10, 102, 105, 102, 53, 114, 70, 81, 121, 90, 106, 99, 85, 70, 73, 76, 100, 115, 57, 81, 81, 72, 114, 105, 52, 72, 75, 107, 70, 119, 81, 74, 65, 72, 54, 119, 79, 113, 89, 78, 87, 120, 73, 73, 43, 89, 117, 101, 54, 109, 101, 78, 88, 77, 66, 80, 103, 74, 115, 56, 49, 110, 99, 103, 72, 10, 97, 66, 107, 87, 116, 89, 81, 56, 50, 74, 43, 79, 85, 72, 117, 104, 97, 99, 122, 78, 52, 108, 116, 43, 112, 53, 113, 80, 106, 79, 65, 54, 90, 88, 76, 48, 56, 53, 47, 99, 51, 120, 107, 100, 69, 80, 83, 67, 83, 66, 80, 83, 88, 81, 74, 66, 65, 73, 104, 75, 71, 100, 101, 66, 10, 102, 47, 56, 117, 75, 120, 48, 76, 73, 105, 115, 71, 69, 104, 90, 88, 66, 114, 106, 57, 81, 97, 109, 69, 118, 82, 71, 48, 80, 88, 101, 77, 69, 88, 116, 115, 116, 107, 82, 120, 52, 47, 68, 109, 68, 66, 83, 112, 68, 113, 89, 83, 78, 88, 77, 109, 120, 49, 87, 81, 83, 100, 112, 115, 10, 120, 80, 48, 70, 109, 49, 47, 114, 50, 43, 117, 70, 121, 80, 119, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10]
        
        // certificate for host 0.0.0.0, self-signed, valid until 2035-12-24
        let certificate:[UInt8] = [45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 77, 73, 73, 66, 56, 84, 67, 67, 65, 86, 111, 67, 67, 81, 68, 54, 77, 52, 43, 80, 75, 87, 97, 57, 57, 106, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 85, 70, 65, 68, 65, 57, 77, 81, 115, 119, 67, 81, 89, 68, 86, 81, 81, 71, 69, 119, 74, 86, 10, 85, 122, 69, 79, 77, 65, 119, 71, 65, 49, 85, 69, 67, 104, 77, 70, 86, 109, 70, 119, 98, 51, 73, 120, 68, 68, 65, 75, 66, 103, 78, 86, 66, 65, 115, 84, 65, 49, 82, 77, 85, 122, 69, 81, 77, 65, 52, 71, 65, 49, 85, 69, 65, 120, 77, 72, 77, 67, 52, 119, 76, 106, 65, 117, 10, 77, 68, 65, 101, 70, 119, 48, 120, 78, 106, 69, 119, 77, 106, 81, 121, 77, 84, 77, 120, 77, 68, 100, 97, 70, 119, 48, 122, 78, 84, 69, 121, 77, 106, 81, 121, 77, 84, 77, 120, 77, 68, 100, 97, 77, 68, 48, 120, 67, 122, 65, 74, 66, 103, 78, 86, 66, 65, 89, 84, 65, 108, 86, 84, 10, 77, 81, 52, 119, 68, 65, 89, 68, 86, 81, 81, 75, 69, 119, 86, 87, 89, 88, 66, 118, 99, 106, 69, 77, 77, 65, 111, 71, 65, 49, 85, 69, 67, 120, 77, 68, 86, 69, 120, 84, 77, 82, 65, 119, 68, 103, 89, 68, 86, 81, 81, 68, 69, 119, 99, 119, 76, 106, 65, 117, 77, 67, 52, 119, 10, 77, 73, 71, 102, 77, 65, 48, 71, 67, 83, 113, 71, 83, 73, 98, 51, 68, 81, 69, 66, 65, 81, 85, 65, 65, 52, 71, 78, 65, 68, 67, 66, 105, 81, 75, 66, 103, 81, 68, 84, 66, 48, 116, 48, 113, 84, 100, 106, 65, 81, 112, 113, 122, 109, 89, 43, 98, 51, 47, 85, 81, 68, 82, 77, 10, 87, 52, 70, 104, 70, 81, 84, 111, 111, 80, 71, 83, 69, 49, 107, 107, 74, 73, 108, 83, 118, 50, 52, 56, 88, 74, 99, 120, 106, 80, 86, 51, 116, 106, 112, 66, 55, 53, 85, 107, 84, 110, 49, 51, 116, 54, 68, 50, 72, 52, 56, 78, 88, 56, 50, 48, 51, 81, 78, 97, 111, 56, 99, 118, 10, 106, 80, 76, 105, 50, 52, 116, 82, 106, 50, 69, 52, 74, 68, 99, 73, 103, 121, 102, 69, 50, 97, 99, 111, 51, 105, 79, 105, 87, 89, 106, 109, 50, 76, 113, 116, 56, 76, 78, 68, 107, 72, 68, 69, 82, 89, 65, 99, 74, 70, 47, 100, 83, 73, 71, 100, 80, 120, 106, 115, 111, 68, 47, 55, 10, 120, 100, 112, 74, 105, 101, 87, 73, 82, 79, 111, 116, 117, 82, 71, 118, 116, 81, 73, 68, 65, 81, 65, 66, 77, 65, 48, 71, 67, 83, 113, 71, 83, 73, 98, 51, 68, 81, 69, 66, 66, 81, 85, 65, 65, 52, 71, 66, 65, 71, 54, 56, 43, 97, 103, 75, 70, 71, 100, 101, 83, 74, 119, 121, 10, 67, 111, 47, 103, 121, 106, 57, 56, 68, 89, 114, 107, 83, 122, 49, 50, 73, 100, 81, 120, 101, 89, 115, 51, 84, 71, 76, 112, 49, 107, 74, 87, 88, 69, 72, 73, 84, 54, 89, 68, 88, 103, 114, 116, 75, 119, 112, 68, 80, 85, 109, 79, 106, 116, 117, 68, 47, 114, 83, 83, 51, 110, 90, 83, 10, 113, 97, 115, 88, 79, 47, 76, 73, 85, 116, 55, 103, 84, 120, 98, 77, 111, 104, 119, 70, 78, 121, 71, 109, 90, 118, 104, 52, 105, 47, 98, 117, 51, 85, 52, 78, 86, 70, 77, 101, 107, 107, 66, 88, 50, 120, 67, 69, 73, 97, 118, 111, 75, 70, 74, 99, 77, 51, 77, 69, 122, 104, 118, 101, 10, 97, 53, 66, 55, 122, 119, 84, 117, 119, 70, 88, 71, 122, 113, 111, 43, 98, 116, 107, 97, 97, 51, 65, 80, 57, 115, 118, 88, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10]
        
        
        let hostname = "0.0.0.0"
        
        // create 128_000 bytes of test data
        var testData:[UInt8] = []
        for _ in 1...1000 {
            testData.append(contentsOf: Array(0...255))
        }
        var serverTestSucces = false
        var clientTestSuccess = false
        var serverError:Error?
        var clientError:Error?
        
        
        let certificates:Certificates = .bytes(certificateBytes: certificate, keyBytes: privateKey, signature: Certificates.Signature.selfSigned)
        
        let server = try TLS.Socket(
            mode: .server,
            hostname: hostname,
            port: 0, // makes the socket bind to any available port
            certificates: certificates,
            verifyHost: false,
            verifyCertificates: false
        )
        
        try server.socket.bind()
        try server.socket.listen()
        
        let assignedAddress = try server.socket.localAddress()
        print("Listening on \(assignedAddress.description)")
        
        let group = DispatchGroup()
        
        group.enter()
        DispatchQueue.global(qos: .default).async {
            do {
                try server.accept()
                var receivedData:[UInt8] = []
                while receivedData.count < testData.count {
                    let newData = try server.receive(max: 65_536)
                    receivedData.append(contentsOf: newData)
                }
                if receivedData == testData {
                    serverTestSucces = true
                }
                try server.send(receivedData) // mirror data back
                try server.close()
            } catch {
                serverError = error
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
        
        group.enter()
        DispatchQueue.global(qos: .default).async {
            do {
                try client.connect(servername: hostname)
                try client.send(testData)
                var receivedData:[UInt8] = []
                while receivedData.count < testData.count {
                    let newData = try client.receive(max: 65_536)
                    receivedData.append(contentsOf: newData)
                }
                if receivedData == testData {
                    clientTestSuccess = true
                }
            } catch {
                clientError = error
            }
            group.leave()
        }
        
        let timeoutInSeconds:Double = 10
        let result = group.wait(timeout: DispatchTime.init(secondsFromNow: timeoutInSeconds))
        guard result == DispatchTimeoutResult.success else {
            XCTFail("Test timed out after \(timeoutInSeconds) seconds. Server error: \(String(describing: serverError)).  Client error: \(String(describing: clientError))")
            return
        }
        if let error = serverError {
            XCTFail("Server encountered an error: \(error).")
            return
        }
        if let error = clientError {
            XCTFail("Client encountered an error: \(error).")
            return
        }
        guard serverTestSucces && clientTestSuccess else {
            XCTFail("Test data was not transmitted correctly.")
            return
        }
        print("Successfully transferred \(testData.count/1000)KB of data from client to server and back again over a TLS connection")
    }
}
