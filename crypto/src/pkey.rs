//! Asymmetric encryption / decryption, signing / verification wrapper.
use std::{
    self,
    fmt::{Debug, Formatter},
    result::Result,
};

use openssl::{hash, pkey, rsa, sign};

use opcua_types::status_code::StatusCode;

#[derive(Copy, Clone)]
pub enum RsaPadding {
    PKCS1,
    OAEP,
}

impl Into<rsa::Padding> for RsaPadding {
    fn into(self) -> rsa::Padding {
        match self {
            RsaPadding::PKCS1 => rsa::Padding::PKCS1,
            RsaPadding::OAEP => rsa::Padding::PKCS1_OAEP,
        }
    }
}

/// This is a wrapper around an `OpenSSL` asymmetric key pair. Since openssl 0.10, the PKey is either
/// a public or private key so we have to differentiate that as well.
pub struct PKey<T> {
    pub(crate) value: pkey::PKey<T>,
}

/// A public key
pub type PublicKey = PKey<pkey::Public>;
// A private key
pub type PrivateKey = PKey<pkey::Private>;

impl<T> Debug for PKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[pkey]")
    }
}

pub trait KeySize {
    fn bit_length(&self) -> usize;

    fn size(&self) -> usize { self.bit_length() / 8 }

    fn calculate_cipher_text_size(&self, data_size: usize, padding: RsaPadding) -> usize {
        let plain_text_block_size = self.plain_text_block_size(padding);
        let block_count = if data_size % plain_text_block_size == 0 {
            data_size / plain_text_block_size
        } else {
            (data_size / plain_text_block_size) + 1
        };
        block_count * self.cipher_text_block_size()
    }

    fn plain_text_block_size(&self, padding: RsaPadding) -> usize {
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

    fn cipher_text_block_size(&self) -> usize {
        self.size()
    }
}

impl KeySize for PrivateKey {
    /// Length in bits
    fn bit_length(&self) -> usize {
        self.value.bits() as usize
    }
}

impl PrivateKey {
    pub fn new(bit_length: u32) -> PrivateKey {
        PKey {
            value: {
                let rsa = rsa::Rsa::generate(bit_length).unwrap();
                pkey::PKey::from_rsa(rsa).unwrap()
            },
        }
    }

    pub fn wrap_private_key(pkey: pkey::PKey<pkey::Private>) -> PrivateKey {
        PrivateKey { value: pkey }
    }

    pub fn from_pem(pem: &[u8]) -> Result<PrivateKey, ()> {
        pkey::PKey::private_key_from_pem(pem)
            .map(|value| PKey { value })
            .map_err(|_| {
                error!("Cannot produce a private key from the data supplied");
            })
    }

    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ()> {
        self.value.private_key_to_pem_pkcs8()
            .map_err(|_| {
                error!("Cannot turn private key to PEM");
            })
    }

    /// Creates a message digest from the specified block of data and then signs it to return a signature
    fn sign(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &mut [u8], padding: RsaPadding) -> Result<usize, StatusCode> {
        trace!("RSA signing");
        if let Ok(mut signer) = sign::Signer::new(message_digest, &self.value) {
            signer.set_rsa_padding(padding.into()).unwrap();
            if signer.update(data).is_ok() {
                return signer.sign_to_vec()
                    .map(|result| {
                        trace!("Signature result, len {} = {:?}, copying to signature len {}", result.len(), result, signature.len());
                        signature.copy_from_slice(&result);
                        result.len()
                    })
                    .map_err(|err| {
                        debug!("Cannot sign data - error = {:?}", err);
                        StatusCode::BadUnexpectedError
                    });
            }
        }
        Err(StatusCode::BadUnexpectedError)
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_hmac_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha1(), data, signature, RsaPadding::PKCS1)
    }
    /// Signs the data using RSA-SHA256
    pub fn sign_hmac_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha256(), data, signature, RsaPadding::PKCS1)
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

        let src_len = src.len();
        while src_idx < src_len {
            // Decrypt and advance
            dst_idx += {
                let src = &src[src_idx..(src_idx + cipher_text_block_size)];
                let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];
                rsa.private_decrypt(src, dst, padding)
                    .map_err(|err| {
                        error!("Decryption failed for key size {}, src idx {}, dst idx {} error - {:?}", cipher_text_block_size, src_idx, dst_idx, err);
                    })?
            };
            src_idx += cipher_text_block_size;
        }
        Ok(dst_idx)
    }
}

impl KeySize for PublicKey {
    /// Length in bits
    fn bit_length(&self) -> usize {
        self.value.bits() as usize
    }
}

impl PublicKey {
    pub fn wrap_public_key(pkey: pkey::PKey<pkey::Public>) -> PublicKey {
        PublicKey { value: pkey }
    }

    /// Verifies that the signature matches the hash / signing key of the supplied data
    fn verify(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &[u8], padding: RsaPadding) -> Result<bool, StatusCode> {
        trace!("RSA verifying, against signature {:?}, len {}", signature, signature.len());
        if let Ok(mut verifier) = sign::Verifier::new(message_digest, &self.value) {
            verifier.set_rsa_padding(padding.into()).unwrap();
            if verifier.update(data).is_ok() {
                return verifier.verify(signature)
                    .map(|result| {
                        trace!("Key verified = {:?}", result);
                        result
                    })
                    .map_err(|err| {
                        debug!("Cannot verify key - error = {:?}", err);
                        StatusCode::BadUnexpectedError
                    });
            }
        }
        Err(StatusCode::BadUnexpectedError)
    }

    /// Verifies the data using RSA-SHA1
    pub fn verify_hmac_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha1(), data, signature, RsaPadding::PKCS1)
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_hmac_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha256(), data, signature, RsaPadding::PKCS1)
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

        let src_len = src.len();
        while src_idx < src_len {
            let bytes_to_encrypt = if src_len < plain_text_block_size {
                src_len
            } else if (src_len - src_idx) < plain_text_block_size {
                src_len - src_idx
            } else {
                plain_text_block_size
            };

            // Encrypt data, advance dst index by number of bytes after encrypted
            dst_idx += {
                let src = &src[src_idx..(src_idx + bytes_to_encrypt)];
                let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];
                rsa.public_encrypt(src, dst, padding)
                    .map_err(|err| {
                        error!("Encryption failed for bytes_to_encrypt {}, key_size {}, src_idx {}, dst_idx {} error - {:?}", bytes_to_encrypt, cipher_text_block_size, src_idx, dst_idx, err);
                    })?
            };

            // Src advances by bytes to encrypt
            src_idx += bytes_to_encrypt;
        }

        Ok(dst_idx)
    }
}
