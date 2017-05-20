use openssl::x509;
use openssl::aes;

use std::marker::{Send};
use std::fmt::{Debug, Result, Formatter};

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
