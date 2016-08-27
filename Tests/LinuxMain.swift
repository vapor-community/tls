import XCTest
@testable import TLSTests

XCTMain([
     testCase(ContextTests.allTests),
     testCase(LiveTests.allTests),
])
