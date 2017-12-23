use std;
use std::marker::Send;
use std::fmt::{Debug, Formatter};
use std::result::Result;

use openssl::pkey;
use openssl::rsa;
use openssl::sign;
use openssl::hash;

use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;

#[derive(Copy, Clone)]
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

    pub fn calculate_cipher_text_size(&self, data_size: usize, padding: RsaPadding) -> usize {
        let plain_text_block_size = self.plain_text_block_size(padding);
        let block_count = if data_size % plain_text_block_size == 0 {
            data_size / plain_text_block_size
        } else {
            (data_size / plain_text_block_size) + 1
        };
        let cipher_text_size = block_count * self.cipher_text_block_size();
        cipher_text_size
    }

    pub fn plain_text_block_size(&self, padding: RsaPadding) -> usize {
        // From RSA_public_encrypt - flen must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5
        // based padding modes, less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING and exactly
        // RSA_size(rsa) for RSA_NO_PADDING.
        //
        // Note other RSA impls use 11 and 42 so this impl will too.
        match padding {
            RsaPadding::PKCS1 => self.size() - 11,
            RsaPadding::OAEP => self.size() - 42,
        }
    }

    pub fn cipher_text_block_size(&self) -> usize {
        self.size()
    }

    /// Encrypts data from src to dst using the specified padding and returns the size of encrypted
    /// data in bytes or an error.
    pub fn public_encrypt(&self, src: &[u8], dst: &mut [u8], padding: RsaPadding) -> Result<usize, ()> {
        let cipher_text_block_size = self.cipher_text_block_size();
        let plain_text_block_size = self.plain_text_block_size(padding);

        // For reference:
        //
        // https://www.openssl.org/docs/man1.0.2/crypto/RSA_public_encrypt.html
        let rsa = self.value.rsa().unwrap();
        let padding: rsa::Padding = padding.into();

        // Encrypt the data in chunks no larger than the key size less padding
        let mut src_idx = 0;
        let mut dst_idx = 0;
        while src_idx < src.len() {
            let bytes_to_encrypt = if src.len() < plain_text_block_size {
                src.len()
            } else if (src.len() - src_idx) < plain_text_block_size {
                src.len() - src_idx
            } else {
                plain_text_block_size
            };

            // Encrypt data, advance dst index by number of bytes after encrypted
            dst_idx += {
                let src = &src[src_idx..(src_idx + bytes_to_encrypt)];
                let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];
                let encrypted_bytes = rsa.public_encrypt(src, dst, padding);
                if encrypted_bytes.is_err() {
                    error!("Encryption failed for bytes_to_encrypt {}, key_size {}, src_idx {}, dst_idx {} error - {:?}", bytes_to_encrypt, cipher_text_block_size, src_idx, dst_idx, encrypted_bytes.unwrap_err());
                    return Err(());
                }
                encrypted_bytes.unwrap()
            };

            // Src advances by bytes to encrypt
            src_idx += bytes_to_encrypt;
        }

        Ok(dst_idx)
    }

    /// Decrypts data in src to dst using the specified padding and returning the size of the decrypted
    /// data in bytes or an error.
    pub fn private_decrypt(&self, src: &[u8], dst: &mut [u8], padding: RsaPadding) -> Result<usize, ()> {
        // decrypt data using our private key
        let cipher_text_block_size = self.cipher_text_block_size();
        let rsa = self.value.rsa().unwrap();
        let padding: rsa::Padding = padding.into();

        // Decrypt the data
        let mut src_idx = 0;
        let mut dst_idx = 0;
        while src_idx < src.len() {
            let src = &src[src_idx..(src_idx + cipher_text_block_size)];
            let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];
            let decrypted_bytes = rsa.private_decrypt(src, dst, padding);
            if decrypted_bytes.is_err() {
                error!("Decryption failed for key size {}, src idx {}, dst idx {} error - {:?}", cipher_text_block_size, src_idx, dst_idx, decrypted_bytes.unwrap_err());
                return Err(());
            }
            src_idx += cipher_text_block_size;
            dst_idx += decrypted_bytes.unwrap();
        }
        Ok(dst_idx)
    }

    /// Creates a message digest from the specified block of data and then signs it to return a signature
    fn sign(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &mut [u8], padding: RsaPadding) -> Result<usize, StatusCode> {
        trace!("RSA signing");
        if let Ok(mut signer) = sign::Signer::new(message_digest, &self.value) {
            signer.pkey_ctx_mut().set_rsa_padding(padding.into()).unwrap();
            if signer.update(data).is_ok() {
                let result = signer.finish();
                if let Ok(result) = result {
                    trace!("Signature result, len {} = {:?}, copying to signature len {}", result.len(), result, signature.len());
                    signature.copy_from_slice(&result);
                    return Ok(result.len());
                } else {
                    debug!("Can't sign data - error = {:?}", result.unwrap_err());
                }
            }
        }
        Err(BadUnexpectedError)
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
        Err(BadUnexpectedError)
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_hmac_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha1(), data, signature, RsaPadding::PKCS1)
    }

    /// Verifies the data using RSA-SHA1
    pub fn verify_hmac_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha1(), data, signature, RsaPadding::PKCS1)
    }

    /// Signs the data using RSA-SHA256
    pub fn sign_hmac_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha256(), data, signature, RsaPadding::PKCS1)
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_hmac_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha256(), data, signature, RsaPadding::PKCS1)
    }
}
