use std;
use std::marker::Send;
use std::fmt::{Debug, Formatter};
use std::result::Result;

use openssl::pkey;
use openssl::rsa;
use openssl::sign;
use openssl::hash;

use opcua_types::StatusCode;
use opcua_types::StatusCode::*;

pub enum RsaPadding {
    PKCS1,
    OAEP
}

impl Into<rsa::Padding> for RsaPadding {
    fn into(self) -> rsa::Padding {
        match self {
            RsaPadding::PKCS1 => rsa::PKCS1_PADDING,
            RsaPadding::OAEP => rsa::PKCS1_OAEP_PADDING,
        }
    }
}

/// This is a wrapper around an `OpenSSL` asymmetric key pair
pub struct PKey {
    pub value: pkey::PKey,
}

impl Debug for PKey {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[pkey]")
    }
}

unsafe impl Send for PKey {}

impl PKey {
    pub fn wrap(pkey: pkey::PKey) -> PKey {
        PKey { value: pkey }
    }

    pub fn new(bit_length: u32) -> PKey {
        PKey {
            value: {
                let rsa = rsa::Rsa::generate(bit_length).unwrap();
                pkey::PKey::from_rsa(rsa).unwrap()
            },
        }
    }

    /// Length in bits
    pub fn bit_length(&self) -> usize {
        self.value.bits() as usize
    }

    /// Size in bytes
    pub fn size(&self) -> usize { self.bit_length() / 8 }

    /// Creates a message digest from the specified block of data and then signs it to return a signature
    fn sign(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &mut [u8], padding: RsaPadding) -> Result<usize, StatusCode> {
        trace!("RSA signing");

        if let Ok(mut signer) = sign::Signer::new(message_digest, &self.value) {
            signer.pkey_ctx_mut().set_rsa_padding(padding.into()).unwrap();
            if signer.update(data).is_ok() {
                let result = signer.finish();
                if let Ok(result) = result {
                    trace!("Signature, len {} = {:?}", result.len(), result);
                    signature.copy_from_slice(&result);
                    return Ok(result.len());
                } else {
                    debug!("Can't sign data - error = {:?}", result.unwrap_err());
                }
            }
        }

        {
            use openssl::hash;
            use openssl::rsa;
            let digest_bytes = hash::hash2(message_digest, data).unwrap();
            let mut sig2 = vec![0u8; self.size()];
            self.value.rsa().unwrap().public_encrypt(&digest_bytes, &mut sig2[..], rsa::PKCS1_PADDING);
            trace!("Signature 2 = {:?}", sig2);
        }

        Err(BAD_UNEXPECTED_ERROR)
    }

    /// Verifies that the signature matches the hash / signing key of the supplied data
    fn verify(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &[u8], padding: RsaPadding) -> Result<bool, StatusCode> {
        trace!("RSA verifying, against signature {:?}, len {}", signature, signature.len());
        if let Ok(mut verifier) = sign::Verifier::new(message_digest, &self.value) {
            verifier.pkey_ctx_mut().set_rsa_padding(padding.into()).unwrap();
            if verifier.update(data).is_ok() {
                let result = verifier.finish(signature);
                if let Ok(result) = result {
                    trace!("Key verified = {:?}", result);
                    return Ok(result);
                } else {
                    debug!("Can't verify key - error = {:?}", result.unwrap_err());
                }
            }
        }
        Err(BAD_UNEXPECTED_ERROR)
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha1(), data, signature, RsaPadding::PKCS1)
    }

    /// Verifies the data using RSA-SHA1
    pub fn verify_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha1(), data, signature, RsaPadding::PKCS1)
    }

    /// Signs the data using RSA-SHA256
    pub fn sign_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha256(), data, signature, RsaPadding::PKCS1)
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha256(), data, signature, RsaPadding::PKCS1)
    }
}
