import Foundation
import CryptoKit

/// A hash size
protocol HashSize {
    /// The size of the digest in bytes
    static var byteCount: Int { get }
}
/// A 160 bit digest size
struct HashSize160Bit: HashSize {
    static var byteCount: Int { 20 }
}
/// A 224 bit digest size
struct HashSize224Bit: HashSize {
    static var byteCount: Int { 28 }
}
/// A 256 bit digest size
struct HashSize256Bit: HashSize {
    static var byteCount: Int { 32 }
}
/// A 384 bit digest size
struct HashSize384Bit: HashSize {
    static var byteCount: Int { 48 }
}
/// A 512 bit digest size
struct HashSize512Bit: HashSize {
    static var byteCount: Int { 64 }
}

/// A type wrapper that implements `Digest` over some bytes
struct AnyDigest<Size>: Equatable, Hashable where Size: HashSize {
    /// The underlying data
    private let data: Data
    
    /// The digest data
    init(data: Data) throws {
        // Validate the data length
        guard data.count == Size.byteCount else {
            throw CryptoKitError.incorrectParameterSize
        }
        
        // Set the data
        self.data = data
    }
}
extension AnyDigest: ContiguousBytes, CustomStringConvertible, Sequence {
    typealias Element = Data.Element
    typealias Iterator = Data.Iterator
    
    func makeIterator() -> Self.Iterator {
        self.data.makeIterator()
    }
    
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.data.withUnsafeBytes(body)
    }
    
    var description: String {
        var hex = ""
        self.data.forEach({ hex += String($0, radix: 16, uppercase: false) })
        return hex
    }
}
extension AnyDigest: Digest where Size: HashSize {
    static var byteCount: Int {
        Size.byteCount
    }
}
