# Encryption

Encryption in OPC UA for Rust is dictated by the specification, particularly:
 
* OPC UA Part 2 describes the security model, threats and objectives.
* OPC UA Part 6 describes the handshake and secure conversation mechanism.
* OPC UA Part 4 describes identity tokens and how UserNameIdentityTokens encrypt data according to security policy. 
* OPC UA Part 7 describes various security policies that a server / client may support.

This document summarizes what algorithms are used by the implementation and issues concerned with moving away from OpenSSL
to a pure Rust crypto library.

## opcua-crypto

OPC UA for Rust is implemented in various crates that encapsulate server, client and common code.

The crypto functionality is contained in the `opcua-crypto` crate that both the server and client depend on.
This provides functions and wrappers that call the `openssl` crate without exposing the internals to the rest of the
code base.
 
OpenSSL is external to Rust and implemented in C so it does add complexity. The `openssl` crate tries its best to
hide it but in reality it can cause configuration problems. Replacing OpenSSL with a pure Rust encryption would be
highly desirable in future.

There are a number of crypto / PKI related crates that offer pure Rust implementations of various cryptographic
services but as yet most are not sufficient to replace OpenSSL. For example, these crates are frequently cited and
popular.

* [`ring`](https://github.com/briansmith/ring) - this is basically a bag of cryptographic functions and so is capable of doing
 everything except X509. However it lacks OAEP padding and perhaps other functions.
* [`webpki`](https://github.com/briansmith/webpki) - this is a higher level crate written over `ring` that offers
  client-side X509 certificate validation. However it does not support creating X509 certs.
* `rcgen` - is a helper that creates self-signed X509 certs wrapping `ring` and the crates below to accomplish it.
    * `pem` - a PEM encoder 
    * `x509-parser` - is an X509 parser

## Security Profiles

OPC UA for Rust supports these OPC UA 1.03 security profiles:

* None - No encryption
* Basic128Rsa15 - AES-128 / SHA-1 / RSA-15
* Basic256 - AES-256 / SHA-1 / RSA-OAEP
* Basic256Sha256 - AES-256 / SHA-256 / RSA-OAEP

It also supports these OPC UA 1.04 policies. 

* Aes128-Sha256-RsaOaep - AES-128 / SHA-256 / RSA-OAEP (a replacement for Basic128Rsa15 with stronger hash & padding)
* Aes256-Sha256-RsaPss - AES256 / SHA-256 / RSA-OAEP with RSA-PSS for signature algorithm

OPC UA 1.04 deprecates Basic128Rsa15 and Basic256 due to perceived weaknesses with SHA-1, but they remain supported
by the implementation.

## Hash

Hashing functions are used to produce message authentication codes and for signing / verification.

* SHA-1 - used to create a filename from an X509 certificate and for comparison purposes of the public key. Also used by signing / verification functions.
* SHA-2 - Used by signing / verification functions. Below it is referred to as SHA-256 because this is the variant
  used in OPC UA to create a 256-bit digest.

## Pseudo-random generator

OPC UA for Rust creates nonces through a secure random function provided by OpenSSL. OpenSSL in turn utilizes 
functions provided by the operating system that ensure sufficient entropy in their result. This is encapsulated by a
couple of functions:

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

Public / private keys are used for asymmetric encryption at a variety of key lengths especially during the handshake 
before symmetric encryption kicks in, but also when passing encrypted user-name password identity tokens to the server. 

OPC UA for Rust doesn't enforce a minimum key length although the OPC UA Specification refers to NIST when it suggests
no less than 1024 bits for the Basic128Rsa15 profile and 2048 bits or more for other profiles. It also recommends
that a key length of < 2048 bits be deprecated.

Private keys are stored in PEM and public certs are stored on disk in DER format and loaded into memory when required.

NOTE: Future impls may favour .pem for both certs & keys to allow for chained signing of certificates.

### Padding

Encrypted data is padded to randomly salt the message and make it harder to decrypt without the correct key.

* PKCS#1 1.5 is an older padding scheme.
* OAEP - Optimal Asymmetric Encryption Padding used by later versions of RSA
* RSA-PSS - Probabilistic Signature Scheme - a form of padding used when making signatures. 

NOTE - `ring` supports PKCS #1 1.5 but does not appear to support OAEP. 
See [issue #691](https://github.com/briansmith/ring/issues/691).

OPC UA 1.04 introduced the Aes256-Sha256-RsaPss security profile that requires a RSA-PSS
padding scheme for signatures.   

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
and not creating one or signing another one. The `rcgen` crate might be a viable way of generating certs and `pem` may be
viable for encoding / decoding them.

### X509 Fields

X509 Certs are generated subject to the requirements of OPC UA which requires a serial number and the first alt subject
name to be an application URI. Subsequent alt subjects can be IP or DNS entries of the host. 

Ordinarily a valid self signed cert can be produced by using the `certificate-creator` tool. 

## PKI infrastructure

All certificates and a server's private key are managed by the `CertificateStore`. Each cert and key is stored on disk in a PEM
encoded file with different directories representing rejected and accepted certs. 

The certificate store is implemented in Rust but uses OpenSSL to read/write certs from PEM format and validate their contents. 
