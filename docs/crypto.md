# Encryption

Encryption in OPC UA for Rust is dictated by the specification, particularly part 2. This document summarizes what algorithms
are used by the implementation and issues concerned with moving away from OpenSSL to a pure Rust crypto
library.

## opcua-crypto

All crypto functionality is contained in the `opcua-crypto` module. This provides functions and wrappers that
call the `openssl` crate without exposing the internals to the rest of the code base. This is a precautionary 
measure so that in the event of porting to another crypto library, all the code that needs changing is in one place.
 
While OpenSSL is the defacto library for encryption it is not without its faults. From a development standpoint the
biggest is that it drags in a huge dependency on an external set of DLLs written in C. The `opcua` crate tries its
best to hide the complexity but in reality it always causes configuration problems. Replacing OpenSSL with a pure
Rust encryption would be highly desirable.

By way of consideration, a number of crypto / PKI related crates have appeared that offer pure Rust implementations
but as yet most are not sufficient to replace OpenSSL. For example, these crates are frequently cited and popular.

* [`ring`](https://github.com/briansmith/ring) - this is basically a bag of cryptographic functions and so is capable of doing
 everything except X509. However it lacks OAEP padding and perhaps other functions.
* [`webpki`](https://github.com/briansmith/webpki) - this is a higher level crate written over `ring` that offers
  X509 certificate validation. However it does not support creating X509 certs.

## Hash

* SHA-1 - used to create a filename from an X509 certificate and for comparison purposes of the public key. Also used by signing / verification functions.
* SHA-2 - Used by signing / verification functions. Below it is referred to as SHA-256 because where it is used, it is
  with a 256-bit digest.

## Pseudo-random generator

OPC UA for Rust creates nonces through through a secure random function provided by OpenSSL. OpenSSL in turn utilizes 
functions provided by the operating system that ensure sufficient entropy in their result. This is encapsulated by a couple of functions:

* `rand::bytes()` fills a buffer with random values
* `rand::byte_string()` returns a `ByteString` with the number of bytes.

## Key derivation

Client and server derive session keys and initialization vectors by exchanging and feeding nonces
into a pseudo random function that generates a key that allows each to talk with the other.

* P_SHA-1 or P_SHA-256 via `hash::p_sha()` are used as pseudo random functions depending on security policy.

## Signing / Verification functions

Messages are signed / verified using a hash based message authentication code (HMAC) using either SHA-1 or SHA-256 according
to the security policy.

* HMAC_SHA1 - via `hash::hmac_sha1()` and `hash::verify_hmac_sha1()`
* HMAC_SHA256 - via `hash::hmac_sha256()` and `hash::verify_hmac_sha256()`

## Symmetric ciphers

Symmetric encryption uses AES with cipher-block-chaining and a key size according to the security policy.
CBC means each block is XOR'd with the previous block prior to encryption while the first block is made unique 
with an initialization vector that was created during key derivation.

* AES_128_CBC - via `AesKey`
* AES_256_CBC - via `AesKey`

## Asymmetric ciphers

Public / private keys are used for asymmetric encryption at a variety of bit lengths especially during the handshake before symmetric
encryption kicks in, but also when passing encrypted user-name password identity tokens to the server. 

Private keys and public certs are stored on disk in PEM format and loaded into memory when required.

Encrypted data is padded to salt the message and make it harder to decrypt.

* PKCS1 - PKCS#1 1.5 is an older padding scheme.
* PKCS1_OAEP - Optimal Asymmetric Encryption Padding used by later versions of RSA

Both forms of padding are required in OPC UA according to the security policy.

NOTE - `ring` supports PKCS #1 1.5 but does not appear to support OAEP. 
See [issue #691](https://github.com/briansmith/ring/issues/691).

## X509 certificates

X509 certificates wrap an asymmetric public key with some meta information and a signature - the issuer, serial number, 
subject alternative names. The signature is either by the private key in the key pair (a self-signed cert)
or by another certificate's private key. 

The biggest difficulty with OPC UA is that it needs the ability to:

* X509 v3 support
* Subject alt names including DNS and IP entries
* Create self-signed certificates (via the `certificate-creator` tool)
* Save/read ASCII armoured (PEM) certificate (and private key) from a buffer
* Verify a certificate's signature and contents (e.g. validity dates)

Future versions of the crate might also want to:

* Check the certificate's signing chain
* Maintain a trust store or folder where trusted root signing keys can be stored. 

All of this is supplied by OpenSSL and has comprehensive support for doing all these things. Whereas it appears to be rather
weak in pure-Rust implementations. For example `webpki` is primarily concerned with parsing an X509,
and not creating one or signing another one.

## PKI infrastructure

All certificates and a server's private key are managed by the `CertificateStore`. Each cert and key is stored on disk in a PEM
encoded file with different directories representing rejected and accepted certs. 

The certificate store is implemented in Rust but uses OpenSSL to read/write certs from PEM format and validate their contents. 
