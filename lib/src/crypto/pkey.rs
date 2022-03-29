// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Asymmetric encryption / decryption, signing / verification wrapper.
use std::{
    self,
    fmt::{self, Debug, Formatter},
    result::Result,
};

use openssl::{hash, pkey, rsa, sign};

use crate::types::status_code::StatusCode;
use openssl::sign::RsaPssSaltlen;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RsaPadding {
    Pkcs1,
    OaepSha1,
    OaepSha256,
    Pkcs1Pss,
}

impl Into<rsa::Padding> for RsaPadding {
    fn into(self) -> rsa::Padding {
        match self {
            RsaPadding::Pkcs1 => rsa::Padding::PKCS1,
            RsaPadding::OaepSha1 => rsa::Padding::PKCS1_OAEP,
            RsaPadding::Pkcs1Pss => rsa::Padding::PKCS1_PSS,
            // Note: This is the right padding but not the right hash and must be handled by special case in the code
            RsaPadding::OaepSha256 => rsa::Padding::PKCS1_OAEP,
        }
    }
}

#[derive(Debug)]
pub struct PKeyError;

impl fmt::Display for PKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKeyError")
    }
}

impl std::error::Error for PKeyError {}

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

    fn size(&self) -> usize {
        self.bit_length() / 8
    }

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
        // flen must not be more than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes,
        // not more than RSA_size(rsa) - 42 for RSA_PKCS1_OAEP_PADDING and exactly RSA_size(rsa)
        // for RSA_NO_PADDING.
        match padding {
            RsaPadding::Pkcs1 => self.size() - 11,
            RsaPadding::OaepSha1 => self.size() - 42,
            RsaPadding::OaepSha256 => self.size() - 66,
            _ => panic!("Unsupported padding"),
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

    pub fn from_pem(pem: &[u8]) -> Result<PrivateKey, PKeyError> {
        pkey::PKey::private_key_from_pem(pem)
            .map(|value| PKey { value })
            .map_err(|_| {
                error!("Cannot produce a private key from the data supplied");
                PKeyError
            })
    }

    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, PKeyError> {
        self.value.private_key_to_pem_pkcs8().map_err(|_| {
            error!("Cannot turn private key to PEM");
            PKeyError
        })
    }

    /// Creates a message digest from the specified block of data and then signs it to return a signature
    fn sign(
        &self,
        message_digest: hash::MessageDigest,
        data: &[u8],
        signature: &mut [u8],
        padding: RsaPadding,
    ) -> Result<usize, StatusCode> {
        trace!("RSA signing");
        if let Ok(mut signer) = sign::Signer::new(message_digest, &self.value) {
            let _ = signer.set_rsa_padding(padding.into());
            let _ = signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH);
            if signer.update(data).is_ok() {
                return signer
                    .sign_to_vec()
                    .map(|result| {
                        trace!(
                            "Signature result, len {} = {:?}, copying to signature len {}",
                            result.len(),
                            result,
                            signature.len()
                        );
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
    pub fn sign_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(
            hash::MessageDigest::sha1(),
            data,
            signature,
            RsaPadding::Pkcs1,
        )
    }

    /// Signs the data using RSA-SHA256
    pub fn sign_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(
            hash::MessageDigest::sha256(),
            data,
            signature,
            RsaPadding::Pkcs1,
        )
    }

    /// Signs the data using RSA-SHA256-PSS
    pub fn sign_sha256_pss(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(
            hash::MessageDigest::sha256(),
            data,
            signature,
            RsaPadding::Pkcs1Pss,
        )
    }

    /// Decrypts data in src to dst using the specified padding and returning the size of the decrypted
    /// data in bytes or an error.
    pub fn private_decrypt(
        &self,
        src: &[u8],
        dst: &mut [u8],
        padding: RsaPadding,
    ) -> Result<usize, PKeyError> {
        // decrypt data using our private key
        let cipher_text_block_size = self.cipher_text_block_size();
        let rsa = self.value.rsa().unwrap();
        let is_oaep_sha256 = padding == RsaPadding::OaepSha256;
        let rsa_padding: rsa::Padding = padding.into();

        // Decrypt the data
        let mut src_idx = 0;
        let mut dst_idx = 0;

        let src_len = src.len();
        while src_idx < src_len {
            // Decrypt and advance
            dst_idx += {
                let src = &src[src_idx..(src_idx + cipher_text_block_size)];
                let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];

                if is_oaep_sha256 {
                    oaep_sha256::decrypt(&rsa, src, dst)
                } else {
                    rsa.private_decrypt(src, dst, rsa_padding)
                }.map_err(|err| {
                    error!("Decryption failed for key size {}, src idx {}, dst idx {}, padding {:?}, error - {:?}", cipher_text_block_size, src_idx, dst_idx, padding, err);
                    PKeyError
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
    fn verify(
        &self,
        message_digest: hash::MessageDigest,
        data: &[u8],
        signature: &[u8],
        padding: RsaPadding,
    ) -> Result<bool, StatusCode> {
        trace!(
            "RSA verifying, against signature {:?}, len {}",
            signature,
            signature.len()
        );
        if let Ok(mut verifier) = sign::Verifier::new(message_digest, &self.value) {
            let _ = verifier.set_rsa_padding(padding.into());
            let _ = verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH);
            if verifier.update(data).is_ok() {
                return verifier
                    .verify(signature)
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
    pub fn verify_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(
            hash::MessageDigest::sha1(),
            data,
            signature,
            RsaPadding::Pkcs1,
        )
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(
            hash::MessageDigest::sha256(),
            data,
            signature,
            RsaPadding::Pkcs1,
        )
    }

    /// Verifies the data using RSA-SHA256-PSS
    pub fn verify_sha256_pss(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(
            hash::MessageDigest::sha256(),
            data,
            signature,
            RsaPadding::Pkcs1Pss,
        )
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

        // For reference:
        //
        // https://www.openssl.org/docs/man1.0.2/crypto/RSA_public_encrypt.html
        let rsa = self.value.rsa().unwrap();
        let is_oaep_sha256 = padding == RsaPadding::OaepSha256;
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

                if is_oaep_sha256 {
                    oaep_sha256::encrypt(&rsa, src, dst)
                } else {
                    rsa.public_encrypt(src, dst, padding)
                }.map_err(|err| {
                    error!("Encryption failed for bytes_to_encrypt {}, src len {}, src_idx {}, dst len {}, dst_idx {}, cipher_text_block_size {}, plain_text_block_size {}, error - {:?}",
                           bytes_to_encrypt, src.len(), src_idx, dst.len(), dst_idx, cipher_text_block_size, plain_text_block_size, err);
                    PKeyError
                })?
            };

            // Src advances by bytes to encrypt
            src_idx += bytes_to_encrypt;
        }

        Ok(dst_idx)
    }
}

/// This module contains a bunch of nasty stuff to implement OAEP-SHA256 since there are no helpers in OpenSSL to do it
///
/// https://stackoverflow.com/questions/17784022/how-to-encrypt-data-using-rsa-with-sha-256-as-hash-function-and-mgf1-as-mask-ge
mod oaep_sha256 {
    use std::ptr;

    use foreign_types::ForeignType;
    use libc::*;
    use openssl::{
        error,
        pkey::{Private, Public},
        rsa::{self, Rsa},
    };
    use openssl_sys::*;

    // This sets up the context for encrypting / decrypting with OAEP + SHA256
    unsafe fn set_evp_ctrl_oaep_sha256(ctx: *mut EVP_PKEY_CTX) {
        EVP_PKEY_CTX_set_rsa_padding(ctx, rsa::Padding::PKCS1_OAEP.as_raw());
        let md = EVP_sha256() as *mut EVP_MD;
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
        // This is a hack because OpenSSL crate doesn't expose this const or a wrapper fn
        const EVP_PKEY_CTRL_RSA_OAEP_MD: c_int = EVP_PKEY_ALG_CTRL + 9;
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_RSA,
            EVP_PKEY_OP_TYPE_CRYPT,
            EVP_PKEY_CTRL_RSA_OAEP_MD,
            0,
            md as *mut c_void,
        );
    }

    /// Special case implementation uses OAEP with SHA256
    pub fn decrypt(
        pkey: &Rsa<Private>,
        from: &[u8],
        to: &mut [u8],
    ) -> Result<usize, error::ErrorStack> {
        let result;
        unsafe {
            let priv_key = EVP_PKEY_new();
            if !priv_key.is_null() {
                EVP_PKEY_set1_RSA(priv_key, pkey.as_ptr());
                let ctx = EVP_PKEY_CTX_new(priv_key, ptr::null_mut());
                EVP_PKEY_free(priv_key);

                if !ctx.is_null() {
                    let _ret = EVP_PKEY_decrypt_init(ctx);
                    set_evp_ctrl_oaep_sha256(ctx);

                    let mut out_len: size_t = to.len();
                    let ret = EVP_PKEY_decrypt(
                        ctx,
                        to.as_mut_ptr(),
                        &mut out_len,
                        from.as_ptr(),
                        from.len(),
                    );
                    if ret > 0 && out_len > 0 {
                        result = Ok(out_len as usize);
                    } else {
                        trace!(
                            "oaep_sha256::decrypt EVP_PKEY_decrypt, ret = {}, out_len = {}",
                            ret,
                            out_len
                        );
                        result = Err(error::ErrorStack::get());
                    }
                    EVP_PKEY_CTX_free(ctx);
                } else {
                    trace!("oaep_sha256::decrypt EVP_PKEY_CTX_new");
                    result = Err(error::ErrorStack::get());
                }
            } else {
                trace!(
                    "oaep_sha256::decrypt EVP_PKEY_new failed, err {}",
                    ERR_get_error()
                );
                result = Err(error::ErrorStack::get());
            }
        }

        result
    }

    /// Special case implementation uses OAEP with SHA256
    pub fn encrypt(
        pkey: &Rsa<Public>,
        from: &[u8],
        to: &mut [u8],
    ) -> Result<usize, error::ErrorStack> {
        let result;
        unsafe {
            let pub_key = EVP_PKEY_new();
            if !pub_key.is_null() {
                EVP_PKEY_set1_RSA(pub_key, pkey.as_ptr());
                let ctx = EVP_PKEY_CTX_new(pub_key, ptr::null_mut());
                EVP_PKEY_free(pub_key);

                if !ctx.is_null() {
                    let _ret = EVP_PKEY_encrypt_init(ctx);
                    set_evp_ctrl_oaep_sha256(ctx);

                    let mut out_len: size_t = to.len();
                    let ret = EVP_PKEY_encrypt(
                        ctx,
                        to.as_mut_ptr(),
                        &mut out_len,
                        from.as_ptr(),
                        from.len(),
                    );
                    if ret > 0 && out_len > 0 {
                        result = Ok(out_len as usize);
                    } else {
                        trace!(
                            "oaep_sha256::encrypt EVP_PKEY_encrypt, ret = {}, out_len = {}",
                            ret,
                            out_len
                        );
                        result = Err(error::ErrorStack::get());
                    }
                    EVP_PKEY_CTX_free(ctx);
                } else {
                    trace!("oaep_sha256::encrypt EVP_PKEY_CTX_new");
                    result = Err(error::ErrorStack::get());
                }
            } else {
                trace!(
                    "oaep_sha256::encrypt EVP_PKEY_new failed, err {}",
                    ERR_get_error()
                );
                result = Err(error::ErrorStack::get());
            }
        }
        result
    }
}
