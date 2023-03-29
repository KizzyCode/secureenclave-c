[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

# SecureEnclave
This packet provides a thin C API to interact with an Apple device's secure enclave co-processor.
With this API you can
 - generate a secure enclave backed ECDSA or ECDH P256 private key with different access-requirements (unlocked once, 
   currently unlocked, user-interactive, user-interactive with biometry, user-interactive with same biometry, ...)
 - compute the public key from the sealed private key blob (obviously)
 - sign a hash value using P256-ECDSA
 - derive a shared secret using P256-ECDH

## Building the library
This library requires the `XCode Command Line Tools` build-toolchain. To build the package, go into the project root and
execute `swift build --configuration=release`. The library artifact is at `.build/release/libSecureEnclave.a`. The
associated API header is located in `Sources/SecureEnclave/include/SecureEnclave.h`.

Have fun\~

## Example
You can find an example in `Sources/SecureEnclave-Example/main.c`. To run the example, go into the project root and
execute `swift run --configuration=release`. Please note that this example requires user-interactive biometric
authentication and thus does not work on devices without enrolled TouchID or FaceID.
