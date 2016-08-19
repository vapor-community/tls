import Foundation

struct Result {
    static let OK = 1.int32
}

extension Int {
    var int32: Int32 {
        return Int32(self)
    }
}

extension FileManager {
    static func fileExists(at path: String) -> Bool {
        let manager = FileManager.default

        var directory: ObjCBool = false
        let exists = manager.fileExists(atPath: path, isDirectory: &directory)
        return exists
    }
}
