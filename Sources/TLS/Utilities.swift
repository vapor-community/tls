import Foundation

struct Result {
    static let OK = 1.int32
}

extension Int {
    var int32: Int32 {
        return Int32(self)
    }
}
