use openssl::x509;
use openssl::aes;

use std::marker::{Send};
use std::fmt::{Debug, Result, Formatter};

#[derive(Debug)]
/// Used to create an X509 cert (and private key)
pub struct X509Data {
    pub key_size: u32,
    pub common_name: String,
    pub organization: String,
    pub organizational_unit: String,
    pub country: String,
    pub state: String,
    pub alt_host_names: Vec<String>,
    pub certificate_duration_days: u32,
}

/// This is a wrapper around the OpenSSL X509 cert
pub struct X509 {
    pub value: x509::X509,
}

impl Debug for X509 {
    fn fmt(&self, f: &mut Formatter) -> Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[x509]")
    }
}

/// This allows certs to be transferred between threads
unsafe impl Send for X509 {}

impl X509 {
    pub fn new(value: x509::X509) -> X509 {
        X509 { value }
    }
}

/// This is a wrapper around the OpenSSL AesKey type
pub struct AesKey {
    pub value: aes::AesKey,
}

impl Debug for AesKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[aes]")
    }
}

impl AesKey {
    pub fn new_encrypt(value: &[u8]) -> AesKey {
        AesKey { value: aes::AesKey::new_encrypt(&value).unwrap() }
    }

    pub fn new_decrypt(value: &[u8]) -> AesKey {
        AesKey { value: aes::AesKey::new_decrypt(&value).unwrap() }
    }
}
