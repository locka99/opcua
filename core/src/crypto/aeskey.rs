use std::marker::Send;
use std::result::Result;

use openssl::symm::{Cipher, Crypter};
use openssl::symm::Mode;

use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;

use crypto::SecurityPolicy;

#[derive(Debug)]
pub struct AesKey {
    value: Vec<u8>,
    security_policy: SecurityPolicy,
}

/// This allows key to be transferred between threads
unsafe impl Send for AesKey {}

impl AesKey {
    pub fn new(security_policy: SecurityPolicy, value: &[u8]) -> AesKey {
        AesKey { value: value.to_vec(), security_policy }
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    fn validate_aes_args(cipher: &Cipher, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        if dst.len() < src.len() + cipher.block_size() {
            error!("Dst buffer is too small {} vs {} + {}", src.len(), dst.len(), cipher.block_size());
            Err(BadUnexpectedError)
        } else if iv.len() != 16 && iv.len() != 32 {
            // ... It would be nice to compare iv size to be exact to the key size here (should be the
            // same) but AesKey doesn't tell us that info. Have to check elsewhere
            error!("IV is not an expected size, len = {}", iv.len());
            Err(BadUnexpectedError)
        } else if src.len() % 16 != 0 {
            panic!("Block size {} is wrong, check stack", src.len());
        } else {
            Ok(())
        }
    }

    fn cipher(&self) -> Cipher {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15 => {
                // Aes128_CBC
                Cipher::aes_128_cbc()
            }
            SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                // Aes256_CBC
                Cipher::aes_256_cbc()
            }
            _ => {
                panic!("Unsupported")
            }
        }
    }

    /// Encrypt or decrypt  data according to the mode
    fn do_cipher(&self, mode: Mode, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, StatusCode> {
        let cipher = self.cipher();

        let _ = Self::validate_aes_args(&cipher, src, iv, dst)?;

        trace!("Encrypting block of size {}", src.len());

        let crypter = Crypter::new(cipher, mode, &self.value, Some(iv));
        if let Ok(mut crypter) = crypter {
            crypter.pad(false);
            let result = crypter.update(src, dst);
            if let Ok(count) = result {
                let result = crypter.finalize(&mut dst[count..]);
                if let Ok(rest) = result {
                    trace!("do cipher size {}", count + rest);
                    Ok(count + rest)
                } else {
                    error!("Encryption error during finalize {:?}", result.unwrap_err());
                    Err(BadUnexpectedError)
                }
            } else {
                error!("Encryption error during update {:?}", result.unwrap_err());
                Err(BadUnexpectedError)
            }
        } else {
            error!("Encryption Error");
            Err(BadUnexpectedError)
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
