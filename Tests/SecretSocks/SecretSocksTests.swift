import XCTest
@testable import SecretSocks

class SecretSocksTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(SecretSocks().text, "Hello, World!")
    }


    static var allTests : [(String, (SecretSocksTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
