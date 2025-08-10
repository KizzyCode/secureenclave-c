#include "include/SecureEnclave.h"
#import "Utils.h"

@import Foundation;
@import SecureEnclave_Swift;


int sep_p256_generate(sep_permissions_t permissions, sep_buf_t* key, sep_buf_t* error) {
    // Generate the key
    NSError* error_ = nil;
    NSData* key_ = [P256 newSealedPrivateKeyWithPermissions:(Permissions)permissions error:&error_];
    if (key_ == nil) {
        [error_ copyToSepBuf:error];
        return -1;
    }
    
    // Convert the private key
    [key_ copyToSepBuf:key];
    return 0;
}


int sep_p256_publickey(const sep_buf_t* key, sep_buf_t* publickey, sep_buf_t* error) {
    // Convert the private key data
    NSData* key_ = [[NSData alloc] initWithSepBuf:key];
    
    // Get the public key
    NSError* error_ = nil;
    NSData* publicKey_ = [P256 publicKeyFromSealedPrivateKey:key_ error:&error_];
    if (publicKey_ == nil) {
        [error_ copyToSepBuf:error];
        return -1;
    }
    
    // Convert the public key
    [publicKey_ copyToSepBuf:publickey];
    return 0;
}


int sep_p256_keyexchange(const sep_buf_t* key, const sep_buf_t* other, sep_buf_t* dhsecret, sep_buf_t* error) {
    // Convert the key data
    NSData* key_ = [[NSData alloc] initWithSepBuf:key];
    NSData* other_ = [[NSData alloc] initWithSepBuf:other];
    
    // Derive the shared secret
    NSError* error_ = nil;
    NSData* sharedSecret_ = [P256 sharedSecretWithPublicKey:other_ usingSealedPrivateKey:key_ error:&error_];
    if (sharedSecret_ == nil) {
        [error_ copyToSepBuf:error];
        return -1;
    }
    
    // Convert the shared secret
    [sharedSecret_ copyToSepBuf:dhsecret];
    return 0;
}


int sep_p256_signhash(const sep_buf_t* key, const sep_buf_t* hash, sep_buf_t* ecdsasig, sep_buf_t* error) {
    // Convert the key data
    NSData* key_ = [[NSData alloc] initWithSepBuf:key];
    NSData* hash_ = [[NSData alloc] initWithSepBuf:hash];
    
    // Derive the shared secret
    NSError* error_ = nil;
    NSData* signature_ = [P256 signDigest:hash_ usingSealedPrivateKey:key_ error:&error_];
    if (signature_ == nil) {
        [error_ copyToSepBuf:error];
        return -1;
    }
    
    // Convert the shared secret
    [signature_ copyToSepBuf:ecdsasig];
    return 0;
}
