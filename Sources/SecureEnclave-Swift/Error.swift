import Foundation
import CryptoKit

/// A secure enclave error
enum SecureEnclaveError: Error {
    /// The secure enclave is unavailable
    case secureEnclaveUnavailable(code: Int = 1, file: String = #file, line: Int = #line)
    /// A `CryptoKit`-error occurred
    case cryptoKit(error: CryptoKit.CryptoKitError, code: Int = 2, file: String = #file, line: Int = #line)
    /// An unspecified `Error` occurred
    case other(error: Error, code: Int = 2, file: String = #file, line: Int = #line)
}
extension SecureEnclaveError {
    /// The error as canonical NSError
    var canonical: NSError {
        // Canonicalize the error
        var canonical: (desc: String, code: Int, file: String, line: Int)! = nil
        switch self {
            case let .secureEnclaveUnavailable(code, file, line):
                canonical = (desc: "Secure enclave is not available", code: code, file: file, line: line)
            case let .cryptoKit(error, code, file, line):
                canonical = (desc: "CryptoKit error: \(error)", code: code, file: file, line: line)
            case let .other(error, code, file, line):
                canonical = (desc: "Unknown error: \(error)", code: code, file: file, line: line)
        }
        
        // Build the NSError
        let userInfo = [
            NSFilePathErrorKey: "\(canonical.file):\(canonical.line)",
            NSLocalizedDescriptionKey: canonical.desc
        ]
        return NSError(domain: "de.KizzyCode.SecureEnclave", code: canonical.code, userInfo: userInfo);
    }
}
extension SecureEnclaveError {
    /// Performs a `do-catch` for `code` and translates any exception into the Obj-C "return nil, set error pointer"-pattern
    static func objcTry<R>(_ error: NSErrorPointer, _ code: () throws -> R, file: String = #file, line: Int = #line) -> R? {
        do {
            // Tries to execute `code`
            return try code()
        } catch let cryptoKitError as CryptoKit.CryptoKitError {
            // Map a `CryptoKitError`
            error?.pointee = Self.cryptoKit(error: cryptoKitError, file: file, line: line).canonical
            return nil
        } catch let otherError {
            // Map an arbitrary error
            error?.pointee = Self.other(error: otherError, file: file, line: line).canonical
            return nil
        }
    }
}
