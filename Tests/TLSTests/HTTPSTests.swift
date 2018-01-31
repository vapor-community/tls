import XCTest

class HTTPSTests: XCTestCase {
    func testGoogle() throws {
        let res = try testHTTPS(hostname: "google.com", request: """
        GET /robots.txt HTTP/1.1\r
        Content-Length: 0\r
        Host: www.google.com\r
        User-Agent: vapor\r
        \r

        """)
        XCTAssert(res.contains("Disallow: /purchases") == true)
    }

    func testHTTPBin() throws {
        let res = try testHTTPS(hostname: "httpbin.org", request: """
        GET /user-agent HTTP/1.1\r
        Content-Length: 0\r
        Host: httpbin.org\r
        User-Agent: vapor\r
        \r

        """)
        XCTAssert(res.contains("vapor") == true)
    }

    func testVapor() throws {
        let res = try testHTTPS(hostname: "vapor.codes", request: """
        GET / HTTP/1.1\r
        Content-Length: 0\r
        Host: vapor.codes\r
        User-Agent: vapor\r
        \r

        """)
        XCTAssert(res.contains("server side swift") == true)
    }

    static let allTests = [
        ("testGoogle", testGoogle),
        ("testHTTPBin", testHTTPBin),
        ("testVapor", testVapor),
    ]
}
