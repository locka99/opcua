//! This module contains crypto related functionality. It is used for establishing
//! trust between a client and server via certificate exchange and validation. It also used for
//! encrypting / decrypting messages and signing messages.
//!
//! The module is an optional component of the stack. If it isn't compiled in, then the OPC UA
//! impl will not support encryption, decryption, signing or verification.

// TODO
use std::path::*;

mod cert_manager;

trait Crypto {
    // This function specifies the crypto capabilities of the compiled software. The value false
    // means the software has no crypto capability so calling other functions below is a waste of time
    // because they are stubs.
    fn is_crypto_enabled() -> bool;

    // Creates an asymmetric key/pair
    fn create_key_pair(public_key_path: &Path, private_key_path: &Path) -> Result<(), ()>;

    // Validates that the certificate is trusted by the server /client
    fn is_certificate_trusted(public_key_path: &Path);

    // Decrypts bytes of data using the specified key
    fn decrypt_bytes();

    // Verifies the specified data using the specified key
    fn verify_signature(data: &[u8], signature: &[u8]);

    // Encrypts bytes using the specified key
    fn encrypt_bytes(data: &[u8], key: &[u8]) -> Vec<u8>;

    // Signs bytes using the specified key
    fn sign_bytes(data: &[u8], key: &[u8]) -> Vec<u8>;
}

