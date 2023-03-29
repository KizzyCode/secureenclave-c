import Foundation
import CryptoKit

/// A interface to a secure enclave backed NIST-P256 key
@objc public final class P256: NSObject {
    /// Generates a new secure enclave bound, sealed private key
    @objc public static func newSealedPrivateKeyWithPermissions(_ permissions: Permissions, error: NSErrorPointer) -> Data? {
        SecureEnclaveError.objcTry(error, {
            // Generate the key
            let accessControl = try permissions.secAccessControl()
            let key = try CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl)
            return key.dataRepresentation
        })
    }
    
    /// Gets the associated public key for the sealed private key in uncompressed SEC 1 representation (`0x04 || x || y`)
    @objc public static func publicKeyFromSealedPrivateKey(_ sealedPrivateKey: Data, error: NSErrorPointer) -> Data? {
        SecureEnclaveError.objcTry(error, {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: sealedPrivateKey)
            return key.publicKey.x963Representation
        })
    }
    
    /// Derives an ECDH shared secret between `self` and a `publicKey` in uncompressed SEC 1 representation (`0x04 || x || y`)
    @objc public static func sharedSecretWithPublicKey(_ publicKey: Data, usingSealedPrivateKey sealedPrivateKey: Data, error: NSErrorPointer) -> Data? {
        SecureEnclaveError.objcTry(error, {
            // Derive a raw shared secret
            let key = try CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: sealedPrivateKey)
            let publicKey = try CryptoKit.P256.KeyAgreement.PublicKey(x963Representation: publicKey)
            let sharedSecret = try key.sharedSecretFromKeyAgreement(with: publicKey)
            return sharedSecret.withUnsafeBytes({ Data($0) })
        })
    }
    
    /// Signs a hash value and returns the signature in raw representation (`r || s`, see https://tools.ietf.org/html/rfc4754)
    @objc public static func signDigest(_ digest: Data, usingSealedPrivateKey sealedPrivateKey: Data, error: NSErrorPointer) -> Data? {
        /// Signs some data
        func sign<Size>(size: Size.Type, key: CryptoKit.SecureEnclave.P256.Signing.PrivateKey) throws -> Data where Size: HashSize {
            let digest = try AnyDigest<Size>(data: digest)
            return try key.signature(for: digest).rawRepresentation
        }
        
        // Try to sign the digest
        return SecureEnclaveError.objcTry(error, {
            // Create the appropriate digest wrapper depending on the byte length
            let key = try CryptoKit.SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: sealedPrivateKey)
            switch digest.count {
                case HashSize160Bit.byteCount: return try sign(size: HashSize160Bit.self, key: key)
                case HashSize224Bit.byteCount: return try sign(size: HashSize224Bit.self, key: key)
                case HashSize256Bit.byteCount: return try sign(size: HashSize256Bit.self, key: key)
                case HashSize384Bit.byteCount: return try sign(size: HashSize384Bit.self, key: key)
                case HashSize512Bit.byteCount: return try sign(size: HashSize512Bit.self, key: key)
                default: throw CryptoKitError.incorrectParameterSize
            }
        })
    }
}
