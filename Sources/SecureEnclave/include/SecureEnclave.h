#ifndef SecureEnclave_h
#define SecureEnclave_h

#include <stdint.h>
#include <stddef.h>


/**
 * @brief A stack-allocated fixed-size buffer for data transfer
 */
typedef struct {
    /**
     * @brief The amount of bytes with `bytes`
     */
    size_t len;
    /**
     * @brief The buffer
     */
    uint8_t bytes[512];
} sep_buf_t;


/**
 * @brief A secure enclave related error
 */
typedef struct {
    /**
     * @brief The error code
     */
    uint64_t code;
    /**
     * @brief The error description as `\0`-terminated string
     */
    sep_buf_t description;
    /**
     * @brief The error location as `\0`-terminated string
     */
    sep_buf_t location;
} sep_error_t;


/**
 * @brief The required permissions to use a key
 *
 * @warning All permissions are exclusive, you MUST NOT `or` them etc. – only use them as-is
 */
typedef enum {
    /**
     * @brief The device must at least be unlocked once after boot to access a key
     *
     * @warning All permissions are exclusive, you MUST NOT `or` them etc. – only use them as-is
     */
    sep_permission_needs_unlock_once = 1,
    /**
     * @brief The device must be currently unlocked to access a key
     *
     * @warning All permissions are exclusive, you MUST NOT `or` them etc. – only use them as-is
     */
    sep_permission_needs_unlock = 2,
    /**
     * @brief The user must authenticate to the device for each key usage
     *
     * @warning All permissions are exclusive, you MUST NOT `or` them etc. – only use them as-is
     */
    sep_permission_needs_interactive_auth = 3,
    /**
     * @brief Needs biometric authentication for each key usage
     *
     * @warning All permissions are exclusive, you MUST NOT `or` them etc. – only use them as-is
     */
    sep_permission_needs_biometry = 4,
    /**
     * @brief Needs the same biometric authentication that has been enrolled when the key was created for each key usage
     *
     * @warning All permissions are exclusive, you MUST NOT `or` them etc. – only use them as-is
     */
    sep_permission_needs_same_biometry = 5
} sep_permissions_t;


/**
 * @brief Generates a new secure enclave backed P256 private key
 *
 * @param permissions The permissions to use a key (will be bound to the key and enforced by the secure enclave)
 * @param key A buffer to write the sealed private key blob into (the blob is encrypted and tied to this secure enclave)
 * @param error A buffer to write potential error information into
 * @return int `0` on success or `-1` on error
 */
int sep_p256_generate(sep_permissions_t permissions, sep_buf_t* key, sep_error_t* error);
/**
 * @brief Gets the associated public key in uncompressed SEC 1 representation (`0x04 || x || y`)
 *
 * @param key The sealed private key blob
 * @param publickey A buffer to write the public key into
 * @param error A buffer to write potential error information into
 * @return int `0` on success or `-1` on error
 */
int sep_p256_publickey(const sep_buf_t* key, sep_buf_t* publickey, sep_error_t* error);
/**
 * @brief Derives an ECDH shared secret in uncompressed SEC 1 representation (`0x04 || x || y`)
 *
 * @param key The sealed private key blob
 * @param other The other party's public key in uncompressed SEC 1 representation (`0x04 || x || y`)
 * @param dhsecret A buffer to write the ECDH shared secret into
 * @param error A buffer to write potential error information into
 * @return int `0` on success or `-1` on error
 */
int sep_p256_keyexchange(const sep_buf_t* key, const sep_buf_t* other, sep_buf_t* dhsecret, sep_error_t* error);
/**
 * @brief Generates an ECDSA signature for the given hash value in it's raw representation (`r || s`,
 *        see https://tools.ietf.org/html/rfc4754)
 *
 * @param key The sealed private key blob
 * @param hash The hash value to sign
 * @param ecdsasig A buffer to write the ECDSA signature into
 * @param error A buffer to write potential error information into
 * @return int `0` on success or `-1` on error
 */
int sep_p256_signhash(const sep_buf_t* key, const sep_buf_t* hash, sep_buf_t* ecdsasig, sep_error_t* error);


#endif /* SecureEnclave_h */
