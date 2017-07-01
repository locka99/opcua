use chrono;

use types::*;
use profiles;
use constants;
use crypto;
use crypto::types::*;

use comms::{SecurityHeader, SymmetricSecurityHeader, AsymmetricSecurityHeader};
use comms::chunk::{ChunkMessageType};

#[derive(Debug)]
pub struct SecureChannelToken {
    pub security_mode: MessageSecurityMode,
    pub security_policy: SecurityPolicy,
    pub secure_channel_id: UInt32,
    pub token_created_at: DateTime,
    pub token_id: UInt32,
    pub token_lifetime: UInt32,
    pub nonce: [u8; 32],
    pub their_nonce: [u8; 32],
    pub their_cert: Option<X509>,
}

impl SecureChannelToken {
    pub fn new() -> SecureChannelToken {
        // Invalid secure channel info by default
        SecureChannelToken {
            security_mode: MessageSecurityMode::None,
            security_policy: SecurityPolicy::None,
            secure_channel_id: 0,
            token_id: 0,
            token_created_at: DateTime::now(),
            token_lifetime: 0,
            nonce: [0; 32],
            their_nonce: [0; 32],
            their_cert: None
        }
    }

    pub fn make_security_header(&self, message_type: ChunkMessageType)-> SecurityHeader {
        match message_type {
            ChunkMessageType::OpenSecureChannel => {
                SecurityHeader::Asymmetric(AsymmetricSecurityHeader::none())
            }
            _ => {
                SecurityHeader::Symmetric(SymmetricSecurityHeader {
                    token_id: self.token_id,
                })
            }
        }
    }

    pub fn create_random_nonce(&mut self) {
        use rand::{self, Rng};
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut self.nonce);
    }

    pub fn nonce_as_byte_string(&self) -> ByteString {
        ByteString::from_bytes(&self.nonce)
    }

    pub fn set_their_nonce(&mut self, their_nonce: &ByteString) -> Result<(), ()> {
        if their_nonce.value.is_some() && their_nonce.value.as_ref().unwrap().len() == self.their_nonce.len() {
            self.their_nonce[..].clone_from_slice(their_nonce.value.as_ref().unwrap());
            Ok(())
        } else {
            Err(())
        }
    }

    /// Test if the token has expired yet
    pub fn token_has_expired(&self) -> bool {
        let now = DateTime::now().as_chrono();
        let token_expires = self.token_created_at.as_chrono() + chrono::Duration::seconds(self.token_lifetime as i64);
        if now.ge(&token_expires) { true } else { false }
    }

    /// Calculate the signature size
    pub fn signature_length(&self) -> usize {
        // TODO check certificate type for signature size
        match self.security_mode {
            MessageSecurityMode::None => 0,
            _ => 20,
        }
    }

    /// Calculate the padding size
    pub fn calc_chunk_padding(&self, byte_length: usize) -> (u8, u8) {
        if self.security_policy != SecurityPolicy::None && self.security_mode != MessageSecurityMode::None {
            let signature_size = self.signature_length();
            let plain_block_size = self.security_policy.plain_block_size();
            let padding_size: u8 = (plain_block_size - ((byte_length + signature_size + 1) % plain_block_size)) as u8;
            let extra_padding_size = 0u8;
            debug!("Padding calculated to be this {} and {}", padding_size, extra_padding_size);
            (padding_size, extra_padding_size)
        } else {
            (0u8, 0u8)
        }
    }

    /// Encode data using security
    pub fn encrypt(&self, src: &[u8], dst: &mut [u8], signature: &mut [u8]) -> Result<(), StatusCode> {
        match self.security_mode {
            MessageSecurityMode::None => {
                // Just copy data to out
                let len = src.len();
                &dst[..len].copy_from_slice(&src[..len]);
                Ok(())
            },
            MessageSecurityMode::Sign => {
                match self.security_policy {
                    SecurityPolicy::None => {
                        panic!("Sign makes no sense without security policy");
                    },
                    SecurityPolicy::Basic128Rsa15 => {

                    },
                    SecurityPolicy::Basic256 => {

                    },
                    SecurityPolicy::Basic256Sha256 => {

                    },
                    _ => {
                        
                    }
                }
                Ok(())
            },
            MessageSecurityMode::SignAndEncrypt => {
                match self.security_policy {
                    SecurityPolicy::None => {
                        panic!("SignAndEncrypt makes no sense without security policy");
                    },
                    SecurityPolicy::Basic128Rsa15 => {

                    },
                    SecurityPolicy::Basic256 => {

                    },
                    SecurityPolicy::Basic256Sha256 => {

                    },
                    _ => {

                    }
                }
                Ok(())
            }
            _ => {
                panic!("Invalid message security mode");
            }
        }
    }

    /// Decrypts and verifies data
    pub fn decrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
       match self.security_mode {
            MessageSecurityMode::None => {
                // Just copy data to out
                let len = src.len();
                &dst[..len].copy_from_slice(&src[..len]);
                Ok(())
            },
            _ => {
                // Use the security policy to decrypt the block using the token
                unimplemented!()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityPolicy {
    Unknown,
    None,
    Basic128Rsa15,
    Basic256,
    Basic256Sha256,
}

impl SecurityPolicy {
    pub fn to_string(&self) -> UAString {
        UAString::from_str(self.to_uri())
    }

    pub fn to_uri(&self) -> &'static str {
        match self {
            &SecurityPolicy::None => profiles::SECURITY_POLICY_NONE,
            &SecurityPolicy::Basic128Rsa15 => profiles::SECURITY_POLICY_BASIC_128_RSA_15,
            &SecurityPolicy::Basic256 => profiles::SECURITY_POLICY_BASIC_256,
            &SecurityPolicy::Basic256Sha256 => profiles::SECURITY_POLICY_BASIC_256_SHA_256,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a uri");
            }
        }
    }

    pub fn asymmetric_signature_algorithm(&self) -> &'static str {
        match self {
            &SecurityPolicy::Basic128Rsa15 => crypto::consts::basic128rsa15::ASYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256 => crypto::consts::basic256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            &SecurityPolicy::Basic256Sha256 => crypto::consts::basic256sha256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    // Plaintext block size in bytes
    pub fn plain_block_size(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => 16,
            &SecurityPolicy::Basic256 => 16,
            &SecurityPolicy::Basic256Sha256 => 16,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    // Cipher block size in bytes
    pub fn cipher_block_size(&self) -> usize {
        // AES uses a 128-bit block size regardless of key length
        match self {
            &SecurityPolicy::Basic128Rsa15 => 16,
            &SecurityPolicy::Basic256 => 16,
            &SecurityPolicy::Basic256Sha256 => 16,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the max key length in bits
    pub fn min_asymmetric_key_length(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => crypto::consts::basic128rsa15::MIN_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256 => crypto::consts::basic256::MIN_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256Sha256 => crypto::consts::basic256sha256::MIN_ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the max key length in bits
    pub fn max_asymmetric_key_length(&self) -> usize {
        match self {
            &SecurityPolicy::Basic128Rsa15 => crypto::consts::basic128rsa15::MAX_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256 => crypto::consts::basic256::MAX_ASYMMETRIC_KEY_LENGTH,
            &SecurityPolicy::Basic256Sha256 => crypto::consts::basic256sha256::MAX_ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    pub fn from_uri(uri: &str) -> SecurityPolicy {
        match uri {
            profiles::SECURITY_POLICY_NONE => SecurityPolicy::None,
            profiles::SECURITY_POLICY_BASIC_128_RSA_15 => SecurityPolicy::Basic128Rsa15,
            profiles::SECURITY_POLICY_BASIC_256 => SecurityPolicy::Basic256,
            profiles::SECURITY_POLICY_BASIC_256_SHA_256 => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy {} is not recognized", uri);
                SecurityPolicy::Unknown
            }
        }
    }

    pub fn from_str(str: &str) -> SecurityPolicy {
        match str {
            constants::SECURITY_POLICY_NONE => SecurityPolicy::None,
            constants::SECURITY_POLICY_BASIC_128_RSA_15 => SecurityPolicy::Basic128Rsa15,
            constants::SECURITY_POLICY_BASIC_256 => SecurityPolicy::Basic256,
            constants::SECURITY_POLICY_BASIC_256_SHA_256 => SecurityPolicy::Basic256Sha256,
            _ => {
                error!("Specified security policy {} is not recognized", str);
                SecurityPolicy::Unknown
            }
        }
    }
}
