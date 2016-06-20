extension SSL {
    public struct Result {
        static let OK = 0.int32
    }
}

extension Int {
    var int32: Int32 {
        return Int32(self)
    }
}
