//! This module contains crypto related functionality. It is used for establishing
//! trust between a client and server via certificate exchange and validation. It also used for
//! encrypting / decrypting messages and signing messages.
//!
//! The module is an optional component of the stack. If it isn't compiled in, then the OPC UA
//! impl will not support encryption, decryption, signing or verification.

use std::path::{Path, PathBuf};

#[derive(Debug)]
/// Used to create an X509 cert (and private key)
pub struct X509CreateCertArgs {
    pub key_size: u32,
    pub pki_path: PathBuf,
    pub overwrite: bool,
    pub common_name: String,
    pub organization: String,
    pub organizational_unit: String,
    pub country: String,
    pub state: String,
    pub alt_host_names: Vec<String>,
    pub certificate_duration_days: u32,
}

/// Tests if crypto is enabled, true for yes it is otherwise false
pub fn is_crypto_enabled() -> bool {
    cfg!(feature = "crypto")
}

trait Crypto {
    // Creates an asymmetric key/pair
    fn create_key_pair(args: X509CreateCertArgs) -> Result<(), ()>;

    // Validates that the certificate is trusted by the server /client
    fn is_certificate_trusted(public_key_path: &Path) -> Result<bool, ()>;

    // Decrypts bytes of data using the specified key
    fn decrypt_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()>;

    // Verifies the specified data using the specified key
    fn verify_signature(data: &[u8], signature: &[u8]) -> Result<bool, ()>;

    // Encrypts bytes using the specified key
    fn encrypt_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()>;

    // Signs bytes using the specified key
    fn sign_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ()>;
}

#[cfg(not(feature = "crypto"))]
pub struct NullCrypto {}

#[cfg(not(feature = "crypto"))]
impl Crypto for NullCrypto {
    fn create_key_pair(_: X509CreateCertArgs) -> Result<(), ()> {
        panic!("Crypto is disabled");
    }

    fn is_certificate_trusted(_: &Path) -> Result<bool, ()> {
        panic!("Crypto is disabled");
    }

    fn decrypt_bytes(_: &[u8], _: &[u8]) -> Result<Vec<u8>, ()> {
        panic!("Crypto is disabled");
    }

    fn verify_signature(_: &[u8], _: &[u8]) -> Result<bool, ()> {
        panic!("Crypto is disabled");
    }

    fn encrypt_bytes(_: &[u8], _: &[u8]) -> Result<Vec<u8>, ()> {
        panic!("Crypto is disabled");
    }

    fn sign_bytes(_: &[u8], _: &[u8]) -> Result<Vec<u8>, ()> {
        panic!("Crypto is disabled");
    }
}

#[cfg(feature = "crypto")]
pub mod cert_manager;

#[cfg(feature = "crypto")]
pub mod sign_verify;

#[cfg(feature = "crypto")]
pub mod encrypt_decrypt;

#[cfg(feature = "crypto")]
pub struct RealCrypto {}

#[cfg(feature = "crypto")]
impl Crypto for RealCrypto {
    fn create_key_pair(args: X509CreateCertArgs) -> Result<(), ()> {
        cert_manager::CertificateStore::create_cert(args)
    }

    fn is_certificate_trusted(_: &Path) -> Result<bool, ()> {
        unimplemented!();
    }

    fn decrypt_bytes(_: &[u8], _: &[u8]) -> Result<Vec<u8>, ()> {
        unimplemented!();
    }

    fn verify_signature(_: &[u8], _: &[u8]) -> Result<bool, ()> {
        unimplemented!();
    }

    fn encrypt_bytes(_: &[u8], _: &[u8]) -> Result<Vec<u8>, ()> {
        unimplemented!();
    }

    fn sign_bytes(_: &[u8], _: &[u8]) -> Result<Vec<u8>, ()> {
        unimplemented!();
    }
}