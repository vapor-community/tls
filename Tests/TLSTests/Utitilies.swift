import Async
import Bits
import TCP
import TLS
#if os(Linux)
    import OpenSSL
#else
    import AppleTLS
#endif
import XCTest

func testHTTPS(hostname: String, request: String) throws -> String {
    let tcpSocket = try TCPSocket(isNonBlocking: true)
    let tcpClient = try TCPClient(socket: tcpSocket)
    var tlsSettings = TLSClientSettings()

    tlsSettings.peerDomainName = hostname

    #if os(Linux)
    let tlsClient = try OpenSSLClient(tcp: tcpClient, using: tlsSettings)
    #else
    let tlsClient = try AppleTLSClient(tcp: tcpClient, using: tlsSettings)
    #endif
    try tlsClient.connect(hostname: hostname, port: 443)

    let done = Promise(String.self)

    let loop = try DefaultEventLoop(label: "codes.vapor.tls.client.test")
    let tlsSource = tlsClient.socket.source(on: loop)
    let tlsSink = tlsClient.socket.sink(on: loop)

    tlsSource.drain { buffer in
        done.complete(String(bytes: buffer, encoding: .utf8) ?? "n/a")
    }.catch { err in
        XCTFail("\(err)")
    }.finally {
        // closed
    }

    let source = PushStream<ByteBuffer>()
    source.output(to: tlsSink)

    let req = request.data(using: .utf8) ?? Data()
    req.withByteBuffer(source.push)

    return try done.future.await(on: loop)
}
