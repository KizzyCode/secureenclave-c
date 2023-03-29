#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "SecureEnclave.h"


/**
 * @brief Hex-prints the given buffer to stdout
 * 
 * @param buffer The buffer to print
 */
void print_buf(const sep_buf_t* buffer) {
    for (size_t index = 0; index < buffer->len; index++) {
        printf("%02x", buffer->bytes[index]);
    }
}


/**
 * @brief Asserts that the given result code is zero, if not, prints the error and exits with status `1`
 * 
 * @param result The result code to check
 * @param error The error struct to print in case of a non-zero result code
 */
void check_result(int result, const sep_error_t* error) {
    if (result != 0) {
        printf("%s at %s [%llu]\n", error->description.bytes, error->location.bytes, error->code);
        exit(1);
    }
}


/**
 * @brief This example creates a new secure enclave backed P256 ECDSA signing key, signs a hash and prints the signature,
 *        hash and the associated public key. Requires biometric authentication.
 */
void ecdsa_example() {
    sep_error_t error = { 0 };
    
    // Create key
    sep_buf_t p256 = { 0 };
    int result = sep_p256_generate(sep_permission_needs_biometry, &p256, &error);
    check_result(result, &error);
    
    // Get pubkey
    sep_buf_t p256_pub = { 0 };
    result = sep_p256_publickey(&p256, &p256_pub, &error);
    check_result(result, &error);
    
    // Create hash
    const uint8_t hash_bytes[32] = {
        0x69, 0xe5, 0x8f, 0xa3, 0x21, 0x51, 0x6f, 0x2b, 0xe5, 0x8f, 0x04, 0x3a, 0x29, 0x41, 0x38, 0x9d,
        0x33, 0x50, 0xca, 0x22, 0x93, 0x88, 0x93, 0x67, 0xcf, 0x2e, 0xc4, 0x87, 0xc0, 0x06, 0x13, 0x03
    };
    sep_buf_t hash = { 0 };
    memcpy(hash.bytes, hash_bytes, sizeof(hash_bytes));
    hash.len = sizeof(hash_bytes);
    
    // Sign data
    sep_buf_t p256_sig = { 0 };
    result = sep_p256_signhash(&p256, &hash, &p256_sig, &error);
    check_result(result, &error);
    
    // Print signature
    printf("Signature: ");
    print_buf(&p256_sig);
    printf("\n");
    
    // Print hash
    printf(" for hash: ");
    print_buf(&hash);
    printf("\n");
    
    // Print pubkey
    printf(" with pubkey: ");
    print_buf(&p256_pub);
    printf("\n\n");
}


/**
 * @brief This example creates a new secure enclave backed P256 ECDH key-exchange key, derives a shared secret and prints
 *        it together with the associated public key. Requires biometric authentication.
 */
void ecdh_example() {
    sep_error_t error = { 0 };
    
    // Create key
    sep_buf_t p256 = { 0 };
    int result = sep_p256_generate(sep_permission_needs_biometry, &p256, &error);
    check_result(result, &error);
    
    // Create pubkey
    const uint8_t pubkey_bytes[65] = {
        0x04, 0x6a, 0x5b, 0x04, 0x47, 0x4d, 0xee, 0x5b, 0x56, 0xb0, 0x18, 0x70, 0x70, 0x84, 0x15, 0x5e,
        0x1e, 0x64, 0xea, 0xcf, 0x20, 0xdb, 0xa3, 0x81, 0x07, 0x79, 0x27, 0x5d, 0x46, 0x35, 0x24, 0xc1,
        0xf0, 0x20, 0xc5, 0x1c, 0x08, 0x98, 0x22, 0xae, 0xe0, 0xe2, 0x3e, 0x14, 0x80, 0x44, 0xa6, 0xde,
        0x79, 0x47, 0xfe, 0xb1, 0xb5, 0x65, 0x04, 0xf7, 0x8b, 0x1b, 0x74, 0xe7, 0xf6, 0x41, 0xc2, 0xd8,
        0x30
    };
    sep_buf_t pubkey = { 0 };
    memcpy(pubkey.bytes, pubkey_bytes, sizeof(pubkey_bytes));
    pubkey.len = sizeof(pubkey_bytes);
    
    // Derive shared secret
    sep_buf_t p256_dhsecret = { 0 };
    result = sep_p256_keyexchange(&p256, &pubkey, &p256_dhsecret, &error);
    check_result(result, &error);
    
    // Print shared secret
    printf("ECDH shared secret: ");
    print_buf(&p256_dhsecret);
    printf("\n");
    
    // Print pubkey
    printf(" with pubkey: ");
    print_buf(&pubkey);
    printf("\n\n");
}


int main(int argc, char** argv) {
    ecdsa_example();
    ecdh_example();
    return 0;
}
