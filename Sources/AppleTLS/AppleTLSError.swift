import Foundation
import Debugging
import Security

/// An SSL Error related to Apple's Security libraries
public struct AppleTLSError: Debuggable {
    public static let readableName = "Apple TLS Error"
    public let identifier: String
    public var reason: String
    public var sourceLocation: SourceLocation?
    public var stackTrace: [String]
    public var possibleCauses: [String]
    public var suggestedFixes: [String]
    
    /// Creates a new Apple TLS error
    public init(
        identifier: String,
        reason: String,
        possibleCauses: [String] = [],
        suggestedFixes: [String] = [],
        source: SourceLocation
    ) {
        self.identifier = identifier
        self.reason = reason
        self.sourceLocation = source
        self.stackTrace = AppleTLSError.makeStackTrace()
        self.possibleCauses = possibleCauses
        self.suggestedFixes = suggestedFixes
    }


    public static func secError(
        _ status: OSStatus,
        possibleCauses: [String] = [],
        suggestedFixes: [String] = [],
        source: SourceLocation
    ) -> AppleTLSError {
        let reason = SecCopyErrorMessageString(status, nil).flatMap { String($0) } ?? "An error occurred when setting up the TLS connection"
        return AppleTLSError(
            identifier: status.description,
            reason: reason,
            possibleCauses: possibleCauses,
            source: source
        )
    }
}
