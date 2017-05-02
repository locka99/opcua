//! This module contains crypto related functionality. It is used for establishing
//! trust between a client and server via certificate exchange and validation. It also used for
//! encrypting / decrypting messages and signing messages.
//!
//! The module is an optional component of the stack. If it isn't compiled in, then the OPC UA
//! impl will not support encryption, decryption, signing or verification.

// TODO
use std::path::*;

mod cert_manager;


#[derive(Debug)]
pub struct X509KeyArgs {
    pub key_size: u32,
    pub pki_path: String,
    pub overwrite: bool,
    pub common_name: String,
    pub organization: String,
    pub organizational_unit: String,
    pub country: String,
    pub state: String,
    pub alt_host_names: Vec<String>,
    pub certificate_duration_days: u32,
}

trait Crypto {
    // This function specifies the crypto capabilities of the compiled software. The value false
    // means the software has no crypto capability so calling other functions below is a waste of time
    // because they are stubs.
    fn is_crypto_enabled() -> bool;

    // Creates an asymmetric key/pair
    fn create_key_pair(args: &X509KeyArgs) -> Result<(), ()>;

    // Validates that the certificate is trusted by the server /client
    fn is_certificate_trusted(public_key_path: &Path) -> Result<bool, ()>;

    // Decrypts bytes of data using the specified key
    fn decrypt_bytes(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, ()>;

    // Verifies the specified data using the specified key
    fn verify_signature(data: &[u8], signature: &[u8]) -> Result<bool, ()>;

    // Encrypts bytes using the specified key
    fn encrypt_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()>;

    // Signs bytes using the specified key
    fn sign_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()>;
}

struct NullCrypto {}

impl Crypto for NullCrypto {
    fn is_crypto_enabled() -> bool {
        false
    }

    fn create_key_pair(args: &X509KeyArgs) -> Result<(), ()> {
        Err(())
    }

    fn is_certificate_trusted(public_key_path: &Path) -> Result<bool, ()> {
        Err(())
    }

    fn decrypt_bytes(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }

    fn verify_signature(data: &[u8], signature: &[u8]) -> Result<bool, ()> {
        Err(())
    }

    fn encrypt_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }

    fn sign_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }
}

pub struct OpenSSLCrypto {}

impl Crypto for OpenSSLCrypto {
    fn is_crypto_enabled() -> bool {
        true
    }

    fn create_key_pair(args: &X509KeyArgs) -> Result<(), ()> {
        Err(())
    }

    fn is_certificate_trusted(public_key_path: &Path) -> Result<bool, ()> {
        Err(())
    }

    fn decrypt_bytes(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }

    fn verify_signature(data: &[u8], signature: &[u8]) -> Result<bool, ()> {
        Err(())
    }

    fn encrypt_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }

    fn sign_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }
}