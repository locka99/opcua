// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Symmetric encryption / decryption wrapper.

use std::result::Result;

use openssl::symm::{Cipher, Crypter, Mode};

use crate::types::status_code::StatusCode;

use super::SecurityPolicy;

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

    fn validate_aes_args(
        cipher: &Cipher,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> Result<(), StatusCode> {
        if dst.len() < src.len() + cipher.block_size() {
            error!(
                "Dst buffer is too small {} vs {} + {}",
                src.len(),
                dst.len(),
                cipher.block_size()
            );
            Err(StatusCode::BadUnexpectedError)
        } else if iv.len() != 16 && iv.len() != 32 {
            // ... It would be nice to compare iv size to be exact to the key size here (should be the
            // same) but AesKey doesn't tell us that info. Have to check elsewhere
            error!("IV is not an expected size, len = {}", iv.len());
            Err(StatusCode::BadUnexpectedError)
        } else if src.len() % 16 != 0 {
            panic!("Block size {} is wrong, check stack", src.len());
        } else {
            Ok(())
        }
    }

    fn cipher(&self) -> Cipher {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Aes128Sha256RsaOaep => {
                // Aes128_CBC
                Cipher::aes_128_cbc()
            }
            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes256Sha256RsaPss => {
                // Aes256_CBC
                Cipher::aes_256_cbc()
            }
            _ => {
                panic!("Unsupported")
            }
        }
    }

    /// Encrypt or decrypt  data according to the mode
    fn do_cipher(
        &self,
        mode: Mode,
        src: &[u8],
        iv: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        let cipher = self.cipher();

        Self::validate_aes_args(&cipher, src, iv, dst)?;

        trace!("Encrypting block of size {}", src.len());

        let crypter = Crypter::new(cipher, mode, &self.value, Some(iv));
        if let Ok(mut crypter) = crypter {
            crypter.pad(false);
            let result = crypter.update(src, dst);
            if let Ok(count) = result {
                crypter
                    .finalize(&mut dst[count..])
                    .map(|rest| {
                        trace!("do cipher size {}", count + rest);
                        count + rest
                    })
                    .map_err(|e| {
                        error!("Encryption error during finalize {:?}", e);
                        StatusCode::BadUnexpectedError
                    })
            } else {
                error!("Encryption error during update {:?}", result.unwrap_err());
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            error!("Encryption Error");
            Err(StatusCode::BadUnexpectedError)
        }
    }

    pub fn block_size(&self) -> usize {
        self.cipher().block_size()
    }

    pub fn iv_length(&self) -> usize {
        self.cipher().iv_len().unwrap()
    }

    pub fn key_length(&self) -> usize {
        self.cipher().key_len()
    }

    pub fn encrypt(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        self.do_cipher(Mode::Encrypt, src, iv, dst)
    }

    /// Decrypts data using AES. The initialization vector is the nonce generated for the secure channel
    pub fn decrypt(&self, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        self.do_cipher(Mode::Decrypt, src, iv, dst)
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
