use chrono;

use opcua_types::*;

use crypto::SecurityPolicy;
use crypto::types::*;

use comms::{SecurityHeader, SymmetricSecurityHeader, AsymmetricSecurityHeader};
use comms::chunk::ChunkMessageType;

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
    pub keys: Option<(AesKey, AesKey, Vec<u8>)>,
    pub their_cert: Option<X509>,
    pub their_keys: Option<(AesKey, AesKey, Vec<u8>)>,
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
            keys: None,
            their_cert: None,
            their_keys: None,
        }
    }

    pub fn make_security_header(&self, message_type: ChunkMessageType) -> SecurityHeader {
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

    /// Part 6
    /// 6.7.5 
    /// Deriving keys Once the SecureChannel is established the Messages are signed and encrypted with
    /// keys derived from the Nonces exchanged in the OpenSecureChannel call. These keys are derived by passing the Nonces to a pseudo-random function which produces a sequence of bytes from a set of inputs. A pseudo-random function is represented by the following function declaration: 
    ///
    /// ```c++
    /// Byte[] PRF( Byte[] secret,  Byte[] seed,  Int32 length,  Int32 offset)
    /// ```
    ///
    /// Where length is the number of bytes to return and offset is a number of bytes from the beginning of the sequence. 
    ///
    /// The lengths of the keys that need to be generated depend on the SecurityPolicy used for the channel.
    /// The following information is specified by the SecurityPolicy: 
    ///
    /// a) SigningKeyLength (from the DerivedSignatureKeyLength);
    /// b) EncryptingKeyLength (implied by the SymmetricEncryptionAlgorithm);
    /// c) EncryptingBlockSize (implied by the SymmetricEncryptionAlgorithm).
    ///
    /// The parameters passed to the pseudo random function are specified in Table 33. 
    ///
    /// Table 33 – Cryptography key generation parameters 
    ///
    /// Key | Secret | Seed | Length | Offset
    /// ClientSigningKey | ServerNonce | ClientNonce | SigningKeyLength | 0
    /// ClientEncryptingKey | ServerNonce | ClientNonce | EncryptingKeyLength | SigningKeyLength
    /// ClientInitializationVector | ServerNonce | ClientNonce | EncryptingBlockSize | SigningKeyLength + EncryptingKeyLength
    /// ServerSigningKey | ClientNonce | ServerNonce | SigningKeyLength | 0
    /// ServerEncryptingKey | ClientNonce | ServerNonce | EncryptingKeyLength | SigningKeyLength
    /// ServerInitializationVector | ClientNonce | ServerNonce | EncryptingBlockSize | SigningKeyLength + EncryptingKeyLength
    ///  
    /// The Client keys are used to secure Messages sent by the Client. The Server keys
    /// are used to secure Messages sent by the Server.
    /// 
    fn derive_keys(&mut self) {
        self.their_keys = Some(self.security_policy.make_secure_channel_keys(&self.their_nonce, &self.nonce));
        self.keys = Some(self.security_policy.make_secure_channel_keys(&self.nonce, &self.their_nonce));
    }

    /// Test if the token has expired yet
    pub fn token_has_expired(&self) -> bool {
        let now = DateTime::now().as_chrono();
        let token_expires = self.token_created_at.as_chrono() + chrono::Duration::seconds(self.token_lifetime as i64);
        if now.ge(&token_expires) { true } else { false }
    }

    pub fn signature_size(&self) -> usize {
        if self.security_policy != SecurityPolicy::None {
            self.security_policy.derived_signature_size()
        } else {
            0
        }
    }

    /// Calculate the padding size
    pub fn calc_chunk_padding(&self, byte_length: usize) -> (u8, u8) {
        if self.security_policy != SecurityPolicy::None && self.security_mode != MessageSecurityMode::None {
            let signature_size = self.security_policy.derived_signature_size();
            let plain_block_size = self.security_policy.plain_block_size();
            let padding_size: u8 = (plain_block_size - ((byte_length + signature_size + 1) % plain_block_size)) as u8;
            let extra_padding_size = 0u8;
            debug!("Padding calculated to be this {} and {}", padding_size, extra_padding_size);
            (padding_size, extra_padding_size)
        } else {
            (0u8, 0u8)
        }
    }

    /// Sign the following block
    fn sign(&self, src: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
        let _ = &(self.keys.as_ref().unwrap()).0;
        // TODO HMAC-1 or 256
        Ok(())
    }

    /// Verify their signature
    fn verify(&self, src: &[u8], signature: &[u8]) -> Result<(), StatusCode> {
        let _ = &(self.their_keys.as_ref().unwrap()).0;
        // TODO HMAC-1 or 256
        Err(BAD_APPLICATION_SIGNATURE_INVALID)
    }


    /// Encrypt the data
    fn encrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        let keys = self.keys.as_ref().unwrap();
        let key = &keys.1;
        let iv = &keys.2;
        let result = key.encrypt(src, iv, dst);
        if result.is_ok() {
            Ok(())
        } else {
            error!("Cannot encrypt data, {}", result.unwrap_err());
            Err(BAD_ENCODING_ERROR)
        }
    }

    /// Decrypt the data
    fn decrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        let keys = self.their_keys.as_ref().unwrap();
        let key = &keys.1;
        let iv = &keys.2;
        let result = key.decrypt(src, iv, dst);
        if result.is_ok() {
            Ok(())
        } else {
            error!("Cannot decrypt data, {}", result.unwrap_err());
            Err(BAD_DECODING_ERROR)
        }
    }

    /// Encode data using security. Destination buffer is expected to be same size as src and expected
    /// to have space for for a signature if a signature is to be appended
    ///
    /// Signing is done first and then encryption
    ///
    /// S - Message Header
    /// S - Security Header
    /// S - Sequence Header - E
    /// S - Body            - E
    /// S - Padding         - E
    ///     Signature       - E
    pub fn encrypt_and_sign_chunk(&self, src: &[u8], sign_info: (usize, usize), encrypt_info: (usize, usize), dst: &mut [u8]) -> Result<(), StatusCode> {
        let (s_from, s_to) = sign_info;
        let (e_from, e_to) = encrypt_info;

        match self.security_mode {
            MessageSecurityMode::None => {
                // Just copy data to out
                dst.copy_from_slice(src);
                Ok(())
            }
            MessageSecurityMode::Sign => {
                match self.security_policy {
                    SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                        let mut signature = vec![0u8; 20];
                        // Sign the message header, security header, sequence header, body, padding
                        self.sign(&src[s_from..s_to], &mut signature)?;
                        &dst[..s_to].copy_from_slice(&src[..s_to]);
                        &dst[s_to..].copy_from_slice(&signature);
                        Ok(())
                    }
                    _ => {
                        panic!("Unsupported security policy");
                    }
                }
            }
            MessageSecurityMode::SignAndEncrypt => {
                match self.security_policy {
                    SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                        let mut dst_tmp = vec![0u8; dst.len()];
                        let mut signature = vec![0u8; 20];
                        // Sign the message header, security header, sequence header, body, padding
                        self.sign(&src[s_from..s_to], &mut signature)?;
                        &dst_tmp[..s_to].copy_from_slice(&src[..s_to]);
                        &dst_tmp[s_to..].copy_from_slice(&signature);
                        // Encrypt the sequence header, payload, signature
                        self.encrypt(&dst_tmp[e_from..e_to], &mut dst[e_from..e_to])?;
                        // Copy the message header / security header
                        &dst[..e_from].copy_from_slice(&dst_tmp[..e_from]);
                        Ok(())
                    }
                    _ => {
                        panic!("Unsupported security policy");
                    }
                }
            }
            _ => {
                panic!("Invalid message security mode");
            }
        }
    }

    /// Decrypts and verifies data.
    ///
    /// S - Message Header
    /// S - Security Header
    /// S - Sequence Header - E
    /// S - Body            - E
    /// S - Padding         - E
    ///     Signature       - E
    pub fn decrypt_and_verify(&self, src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        match self.security_mode {
            MessageSecurityMode::None => {
                // Just copy data to out
                let len = src.len();
                &dst[..len].copy_from_slice(&src[..len]);
                Ok(())
            }
            MessageSecurityMode::Sign => {
                match self.security_policy {
                    SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                        Ok(())
                    }
                    _ => {
                        panic!("Unsupported security policy");
                    }
                }
            }
            MessageSecurityMode::SignAndEncrypt => {
                match self.security_policy {
                    SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                        Ok(())
                    }
                    _ => {
                        panic!("Unsupported security policy");
                    }
                }
            }
            _ => {
                // Use the security policy to decrypt the block using the token
                unimplemented!()
            }
        }
    }
}
