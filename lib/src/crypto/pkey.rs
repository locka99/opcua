// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Asymmetric encryption / decryption, signing / verification wrapper.
use std::{
    self,
    fmt::{self, Debug, Formatter},
    result::Result,
};

use rand;
use rsa::pkcs1;
use rsa::pkcs1v15;
use rsa::pkcs8;
use rsa::pss;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha1;
use sha2;

use x509_cert;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::types::status_code::StatusCode;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RsaPadding {
    Pkcs1,
    OaepSha1,
    OaepSha256,
}

#[derive(Debug)]
pub struct PKeyError;

impl fmt::Display for PKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKeyError")
    }
}

impl std::error::Error for PKeyError {}

impl From<pkcs8::Error> for PKeyError {
    fn from(_err: pkcs8::Error) -> Self {
        PKeyError
    }
}

impl From<pkcs1::Error> for PKeyError {
    fn from(_err: pkcs1::Error) -> Self {
        PKeyError
    }
}

impl From<rsa::Error> for PKeyError {
    fn from(_err: rsa::Error) -> Self {
        PKeyError
    }
}

/// This is a wrapper around an asymmetric key pair. Since the PKey is either
/// a public or private key so we have to differentiate that as well.
pub struct PKey<T> {
    pub(crate) value: T,
}

/// A public key
pub type PublicKey = PKey<RsaPublicKey>;
// A private key
pub type PrivateKey = PKey<RsaPrivateKey>;

impl<T> Debug for PKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[pkey]")
    }
}

pub trait KeySize {
    fn bit_length(&self) -> usize {
        self.size() * 8
    }

    fn size(&self) -> usize;

    //the following functions is only used in secure channel
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
        // the maximum plain text size block is given by
        // for pkcs#1 v1.5 , keyLength - 11
        // for oaep  keyLength -2 hsize -2
        // where all sizes are in bytes
        // sha256 size is 256bits => 32 bytes,
        //sha1 size is 160bits => 20 bytes

        match padding {
            RsaPadding::Pkcs1 => self.size() - 11,
            RsaPadding::OaepSha1 => self.size() - 42,
            RsaPadding::OaepSha256 => self.size() - 66,
        }
    }

    fn cipher_text_block_size(&self) -> usize {
        self.size()
    }
}

impl KeySize for PrivateKey {
    /// Length in bits
    fn size(&self) -> usize {
        use rsa::traits::PublicKeyParts;
        self.value.size()
    }
}

impl PrivateKey {
    pub fn new(bit_length: u32) -> PrivateKey {
        let mut rng = rand::thread_rng();

        let key = RsaPrivateKey::new(&mut rng, bit_length as usize).unwrap();
        PKey { value: key }
    }

    pub fn read_pem_file(path: &std::path::Path) -> Result<PrivateKey, PKeyError> {
        use pkcs8::DecodePrivateKey;
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let r = RsaPrivateKey::read_pkcs8_pem_file(path);
        match r {
            Err(_) => {
                let val = RsaPrivateKey::read_pkcs1_pem_file(path)?;
                Ok(PKey { value: val })
            }
            Ok(val) => Ok(PKey { value: val }),
        }
    }

    pub fn from_pem(bytes: &[u8]) -> Result<PrivateKey, PKeyError> {
        use pkcs8::DecodePrivateKey;
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let converted = std::str::from_utf8(bytes);
        match converted {
            Err(_) => Err(PKeyError),
            Ok(pem) => {
                let r = RsaPrivateKey::from_pkcs8_pem(pem);
                match r {
                    Err(_) => {
                        let val = RsaPrivateKey::from_pkcs1_pem(pem)?;
                        Ok(PKey { value: val })
                    }
                    Ok(val) => Ok(PKey { value: val }),
                }
            }
        }
    }

    pub fn to_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        use pkcs8::EncodePrivateKey;

        self.value.to_pkcs8_der()
    }

    pub fn public_key_to_info(&self) -> x509_cert::spki::Result<SubjectPublicKeyInfoOwned> {
        use rsa::pkcs8::EncodePublicKey;
        SubjectPublicKeyInfoOwned::try_from(
            self.value
                .to_public_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
    }

    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            value: self.value.to_public_key(),
        }
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        let mut rng = rand::thread_rng();
        let signing_key = pkcs1v15::SigningKey::<sha1::Sha1>::new(self.value.clone());
        match signing_key.try_sign_with_rng(&mut rng, data) {
            Err(_) => Err(StatusCode::BadUnexpectedError),
            Ok(signed) => {
                let val = signed.to_vec();
                signature.copy_from_slice(&val);
                Ok(val.len())
            }
        }
    }

    /// Signs the data using RSA-SHA256
    pub fn sign_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        let mut rng = rand::thread_rng();
        let signing_key = pkcs1v15::SigningKey::<sha2::Sha256>::new(self.value.clone());
        match signing_key.try_sign_with_rng(&mut rng, data) {
            Err(_) => Err(StatusCode::BadUnexpectedError),
            Ok(signed) => {
                let val = signed.to_vec();
                signature.copy_from_slice(&val);
                Ok(val.len())
            }
        }
    }

    /// Signs the data using RSA-SHA256-PSS
    pub fn sign_sha256_pss(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        let mut rng = rand::thread_rng();
        let signing_key = pss::BlindedSigningKey::<sha2::Sha256>::new(self.value.clone());
        match signing_key.try_sign_with_rng(&mut rng, data) {
            Err(_) => Err(StatusCode::BadUnexpectedError),
            Ok(signed) => {
                let val = signed.to_vec();
                signature.copy_from_slice(&val);
                Ok(val.len())
            }
        }
    }

    fn pkcs1_decrypt(&self, src: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        self.value.decrypt(Pkcs1v15Encrypt, src)
    }

    fn oaepsha1_decrypt(&self, src: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        let padding = Oaep::new::<sha1::Sha1>();
        self.value.decrypt(padding, src)
    }

    fn oaepsha2_decrypt(&self, src: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        let padding = Oaep::new::<sha2::Sha256>();
        self.value.decrypt(padding, src)
    }

    /// Decrypts data in src to dst using the specified padding and returning the size of the decrypted
    /// data in bytes or an error.
    pub fn private_decrypt(
        &self,
        src: &[u8],
        dst: &mut [u8],
        padding: RsaPadding,
    ) -> Result<usize, PKeyError> {
        let cipher_text_block_size = self.cipher_text_block_size();

        // Decrypt the data
        let mut src_idx = 0;
        let mut dst_idx = 0;

        let src_len = src.len();
        while src_idx < src_len {
            let src_end_index = src_idx + cipher_text_block_size;

            // Decrypt and advance
            dst_idx += {
                let src = &src[src_idx..src_end_index];
                let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];

                let decrypted;
                match padding {
                    RsaPadding::OaepSha256 => decrypted = self.oaepsha2_decrypt(src)?,
                    RsaPadding::Pkcs1 => decrypted = self.pkcs1_decrypt(src)?,
                    RsaPadding::OaepSha1 => decrypted = self.oaepsha1_decrypt(src)?,
                }

                let size = decrypted.len();
                if size == dst.len() {
                    dst.copy_from_slice(&decrypted);
                } else {
                    dst[0..size].copy_from_slice(&decrypted);
                }
                size
            };
            src_idx = src_end_index;
        }
        Ok(dst_idx)
    }
}

impl KeySize for PublicKey {
    /// Length in bits
    fn size(&self) -> usize {
        use rsa::traits::PublicKeyParts;
        self.value.size()
    }
}

impl PublicKey {
    /// Verifies the data using RSA-SHA1
    pub fn verify_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        let verifying_key = pkcs1v15::VerifyingKey::<sha1::Sha1>::new(self.value.clone());
        let r = pkcs1v15::Signature::try_from(signature);
        match r {
            Err(_) => Err(StatusCode::BadUnexpectedError),
            Ok(val) => match verifying_key.verify(data, &val) {
                Err(_) => Ok(false),
                _ => Ok(true),
            },
        }
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha256>::new(self.value.clone());
        let r = pkcs1v15::Signature::try_from(signature);
        match r {
            Err(_) => Err(StatusCode::BadUnexpectedError),
            Ok(val) => match verifying_key.verify(data, &val) {
                Err(_) => Ok(false),
                _ => Ok(true),
            },
        }
    }

    /// Verifies the data using RSA-SHA256-PSS
    pub fn verify_sha256_pss(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        let verifying_key = pss::VerifyingKey::<sha2::Sha256>::new(self.value.clone());
        let r = pss::Signature::try_from(signature);
        match r {
            Err(_) => Err(StatusCode::BadUnexpectedError),
            Ok(val) => match verifying_key.verify(data, &val) {
                Err(_) => Ok(false),
                _ => Ok(true),
            },
        }
    }

    fn pkcs1_encrypt(&self, src: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        self.value.encrypt(&mut rng, Pkcs1v15Encrypt, src)
    }

    fn oaepsha1_encrypt(&self, src: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<sha1::Sha1>();
        self.value.encrypt(&mut rng, padding, src)
    }

    fn oaepsha2_encrypt(&self, src: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<sha2::Sha256>();
        self.value.encrypt(&mut rng, padding, src)
    }

    fn encrypt_data_chunk(&self, src: &[u8], padding: RsaPadding) -> Result<Vec<u8>, PKeyError> {
        let r: rsa::errors::Result<Vec<u8>>;
        match padding {
            RsaPadding::OaepSha256 => r = self.oaepsha2_encrypt(src),
            RsaPadding::Pkcs1 => r = self.pkcs1_encrypt(src),
            RsaPadding::OaepSha1 => r = self.oaepsha1_encrypt(src),
        }

        match r {
            Err(_) => Err(PKeyError),
            Ok(val) => Ok(val),
        }
    }

    /// Encrypts data from src to dst using the specified padding and returns the size of encrypted
    /// data in bytes or an error.
    pub fn public_encrypt(
        &self,
        src: &[u8],
        dst: &mut [u8],
        padding: RsaPadding,
    ) -> Result<usize, PKeyError> {
        let cipher_text_block_size = self.cipher_text_block_size();
        let plain_text_block_size = self.plain_text_block_size(padding);

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

            let src_end_index = src_idx + bytes_to_encrypt;

            // Encrypt data, advance dst index by number of bytes after encrypted
            dst_idx += {
                let src = &src[src_idx..src_end_index];

                let encrypted = self.encrypt_data_chunk(src, padding)?;
                dst[dst_idx..(dst_idx + cipher_text_block_size)].copy_from_slice(&encrypted);
                encrypted.len()
            };

            // Src advances by bytes to encrypt
            src_idx = src_end_index;
        }

        Ok(dst_idx)
    }
}
