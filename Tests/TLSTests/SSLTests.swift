import Async
import Bits
import TCP
import TLS
import XCTest
#if os(Linux)
    import OpenSSL
#else
    import AppleTLS
#endif

class SSLTests: XCTestCase {
    func testClientBlocking() throws {
        let tcpSocket = try TCPSocket(isNonBlocking: false)
        let tcpClient = try TCPClient(socket: tcpSocket)
        let tlsSettings = TLSClientSettings()
        #if os(Linux)
            let tlsClient = try OpenSSLClient(tcp: tcpClient, using: tlsSettings)
        #else
            let tlsClient = try AppleTLSClient(tcp: tcpClient, using: tlsSettings)
        #endif
        sleep(1) // helps prevent EINTR?
        try tlsClient.connect(hostname: "google.com", port: 443)
        try tlsClient.socket.handshake()
        let req = "GET /robots.txt HTTP/1.1\r\nContent-Length: 0\r\nHost: www.google.com\r\nUser-Agent: hi\r\n\r\n".data(using: .utf8)!
        _ = try tlsClient.socket.write(from: req.withByteBuffer { $0 })
        var res = Data(count: 4096)
        _ = try tlsClient.socket.read(into: res.withMutableByteBuffer { $0 })
        print(String(data: res, encoding: .ascii)!)
    }

    func testClient() throws {
        let tcpSocket = try TCPSocket(isNonBlocking: true)
        let tcpClient = try TCPClient(socket: tcpSocket)
        let tlsSettings = TLSClientSettings()
        #if os(Linux)
            let tlsClient = try OpenSSLClient(tcp: tcpClient, using: tlsSettings)
        #else
            let tlsClient = try AppleTLSClient(tcp: tcpClient, using: tlsSettings)
        #endif
        try tlsClient.connect(hostname: "google.com", port: 443)

        let done = Promise(Void.self)

        let clientLoop = try DefaultEventLoop(label: "codes.vapor.tls.client")
        let tlsSource = tlsClient.socket.source(on: clientLoop)
        let tlsSink = tlsClient.socket.sink(on: clientLoop)

        tlsSource.drain { buffer in
            let res = Data(buffer)
            XCTAssertTrue(String(data: res, encoding: .utf8)!.contains("User-agent: *"))
            done.complete()
        }.catch { err in
            XCTFail("\(err)")
        }.finally {
            // closed
        }

        let source = PushStream<ByteBuffer>()
        source.output(to: tlsSink)

        let req = "GET /robots.txt HTTP/1.1\r\nContent-Length: 0\r\nHost: www.google.com\r\nUser-Agent: hi\r\n\r\n".data(using: .utf8)!
        source.push(req.withByteBuffer { $0 })

        try done.future.await(on: clientLoop)
    }

    func testClient2() {
        do {
            let tcpSocket = try TCPSocket(isNonBlocking: true)
            let tcpClient = try TCPClient(socket: tcpSocket)
            let tlsSettings = TLSClientSettings()
            #if os(Linux)
            let tlsClient = try OpenSSLClient(tcp: tcpClient, using: tlsSettings)
            #else
            let tlsClient = try AppleTLSClient(tcp: tcpClient, using: tlsSettings)
            #endif
            try tlsClient.connect(hostname: "httpbin.org", port: 443)

            let done = Promise(Void.self)

            let loop = try DefaultEventLoop(label: "codes.vapor.tls.client.httpbin")
            let tlsSource = tlsClient.socket.source(on: loop)
            let tlsSink = tlsClient.socket.sink(on: loop)

            tlsSource.drain { buffer in
                print(String(bytes: buffer, encoding: .utf8) ?? "n/a")
                done.complete()
            }.catch { err in
                XCTFail("\(err)")
            }.finally {
                // closed
            }

            let source = PushStream<ByteBuffer>()
            source.output(to: tlsSink)

            let req = """
            GET /ip HTTP/1.1\r
            Content-Length: 0\r
            Host: httpbin.org\r
            User-Agent: vapor\r
            \r

            """.data(using: .utf8) ?? Data()
            req.withByteBuffer(source.push)

            try done.future.await(on: loop)
        } catch {
            XCTFail("\(error)")
        }
    }

    static let allTests = [
        ("testClientBlocking", testClientBlocking),
        ("testClient", testClient),
        ("testClient2", testClient2),
    ]
}
