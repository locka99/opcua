// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Symmetric encryption / decryption wrapper.

use std::result::Result;

use aes;
use aes::cipher::{
    block_padding::NoPadding, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut,
    KeyIvInit,
};
use cbc;

use crate::types::status_code::StatusCode;

use super::SecurityPolicy;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const AES_BLOCK_SIZE: usize = 16;
const AES128_KEY_SIZE: usize = 16;
const AES256_KEY_SIZE: usize = 32;

type AesArray128 = GenericArray<u8, <aes::Aes128 as aes::cipher::BlockSizeUser>::BlockSize>;
type AesArray256 = GenericArray<u8, <aes::Aes256 as aes::cipher::KeySizeUser>::KeySize>;

type EncryptResult = Result<usize, StatusCode>;

impl From<cbc::cipher::inout::PadError> for StatusCode {
    fn from(_err: cbc::cipher::inout::PadError) -> Self {
        StatusCode::BadUnexpectedError
    }
}

impl From<cbc::cipher::inout::block_padding::UnpadError> for StatusCode {
    fn from(_err: cbc::cipher::inout::block_padding::UnpadError) -> Self {
        StatusCode::BadUnexpectedError
    }
}

#[derive(Debug)]
pub struct AesKey {
    value: Vec<u8>,
    security_policy: SecurityPolicy,
}
impl AesKey {
    pub fn new(security_policy: SecurityPolicy, value: &[u8]) -> AesKey {
        AesKey {
            value: value.to_vec(),
            security_policy,
        }
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    fn validate_aes_args(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        if dst.len() < src.len() + self.block_size() {
            error!(
                "Dst buffer is too small {} vs {} + {}",
                src.len(),
                dst.len(),
                self.block_size()
            );
            Err(StatusCode::BadUnexpectedError)
        } else if iv.len() != self.iv_length() {
            // ... It would be nice to compare iv size to be exact to the key size here (should be the
            // same) but AesKey doesn't tell us that info. Have to check elsewhere
            error!("IV is not an expected size, len = {}", iv.len());
            Err(StatusCode::BadUnexpectedError)
        } else if src.len() % self.block_size() != 0 {
            panic!("Block size {} is wrong, check stack", src.len());
        } else {
            Ok(())
        }
    }

    fn encrypt_aes128_cbc(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> EncryptResult {
        self.validate_aes_args(src, iv, dst)?;
        Aes128CbcEnc::new(
            AesArray128::from_slice(&self.value),
            AesArray128::from_slice(iv),
        )
        .encrypt_padded_b2b_mut::<NoPadding>(src, dst)?;
        Ok(src.len())
    }

    fn encrypt_aes256_cbc(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> EncryptResult {
        self.validate_aes_args(src, iv, dst)?;
        Aes256CbcEnc::new(
            AesArray256::from_slice(&self.value),
            AesArray128::from_slice(iv),
        )
        .encrypt_padded_b2b_mut::<NoPadding>(src, dst)?;
        Ok(src.len())
    }

    fn decrypt_aes128_cbc(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> EncryptResult {
        self.validate_aes_args(src, iv, dst)?;
        Aes128CbcDec::new(
            AesArray128::from_slice(&self.value),
            AesArray128::from_slice(iv),
        )
        .decrypt_padded_b2b_mut::<NoPadding>(src, dst)?;
        Ok(src.len())
    }

    fn decrypt_aes256_cbc(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> EncryptResult {
        self.validate_aes_args(src, iv, dst)?;
        Aes256CbcDec::new(
            AesArray256::from_slice(&self.value),
            AesArray128::from_slice(iv),
        )
        .decrypt_padded_b2b_mut::<NoPadding>(src, dst)?;
        Ok(src.len())
    }

    pub fn block_size(&self) -> usize {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes256Sha256RsaPss => AES_BLOCK_SIZE,
            _ => 0,
        }
    }

    pub fn iv_length(&self) -> usize {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes256Sha256RsaPss => AES_BLOCK_SIZE,
            _ => 0,
        }
    }

    pub fn key_length(&self) -> usize {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Aes128Sha256RsaOaep => AES128_KEY_SIZE,

            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes256Sha256RsaPss => AES256_KEY_SIZE,
            _ => 0,
        }
    }

    pub fn encrypt(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> EncryptResult {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Aes128Sha256RsaOaep => {
                self.encrypt_aes128_cbc(src, iv, dst)
            }

            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes256Sha256RsaPss => self.encrypt_aes256_cbc(src, iv, dst),

            _ => Err(StatusCode::BadUnexpectedError),
        }
    }

    /// Decrypts data using AES. The initialization vector is the nonce generated for the secure channel
    pub fn decrypt(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> EncryptResult {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Aes128Sha256RsaOaep => {
                self.decrypt_aes128_cbc(src, iv, dst)
            }

            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes256Sha256RsaPss => self.decrypt_aes256_cbc(src, iv, dst),

            _ => Err(StatusCode::BadUnexpectedError),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn test_aeskey_cross_thread() {
        let v: [u8; 5] = [1, 2, 3, 4, 5];
        let k = AesKey::new(SecurityPolicy::Basic256, &v);
        let child = thread::spawn(move || {
            println!("k={:?}", k);
        });
        let _ = child.join();
    }
}
