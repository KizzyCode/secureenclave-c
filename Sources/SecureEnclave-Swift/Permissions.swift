import Foundation
import CryptoKit

/// The required permissions to use a key
@objc public enum Permissions: Int {
    /// The device must at least be unlocked once after boot to access a key
    case needsUnlockOnce = 1
    /// The device must be currently unlocked to access a key
    case needsUnlock = 2
    /// The user must authenticate to the device for each key usage
    case needsInteractiveAuth = 3
    /// Needs biometric authentication for each key usage
    case needsBiometry = 4
    /// Needs exactly the same biometric authentication that has been enrolled curing key creation for each key usage
    case needsSameBiometry = 5
}
extension Permissions {
    /// The permissions as `SecAccessControl` object
    func secAccessControl() throws -> SecAccessControl {
        // Build the appropriate ACL
        var acl: (protection: CFTypeRef, flags: SecAccessControlCreateFlags)! = nil
        switch self {
            case .needsUnlockOnce: acl = (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage)
            case .needsUnlock: acl = (kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage)
            case .needsInteractiveAuth: acl = (kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .and, .userPresence])
            case .needsBiometry: acl = (kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .and, .biometryAny])
            case .needsSameBiometry: acl = (kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .and, .biometryCurrentSet])
        }
        
        // Create the access control
        var error: Unmanaged<CFError>? = nil
        let secAccessControl = SecAccessControlCreateWithFlags(nil, acl.protection, acl.flags, &error)
        guard error == nil else {
            // Throw the error
            let error = error!.takeRetainedValue()
            throw error
        }
        
        // Unwrap the value
        guard let secAccessControl = secAccessControl else {
            fatalError("successful call to `SecAccessControlCreateWithFlags` did not yield a value?!")
        }
        return secAccessControl
    }
}
