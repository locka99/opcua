use std::sync::{Arc, Mutex};
use std::ops::Range;

use chrono;

use openssl::rsa::*;

use opcua_types::*;

use crypto::SecurityPolicy;
use crypto::CertificateStore;
use crypto::types::*;
use crypto::hash;

use comms::{SecurityHeader, SymmetricSecurityHeader, AsymmetricSecurityHeader, MESSAGE_CHUNK_HEADER_SIZE, SEQUENCE_HEADER_SIZE};
use comms::message_chunk::MessageChunkType;

/// Holds all of the security information related to this session
#[derive(Debug)]
pub struct SecureChannel {
    /// The security mode for the connection, None, Sign, SignAndEncrypt
    pub security_mode: MessageSecurityMode,
    /// The security policy for the connection, None or Encryption/Signing settings
    pub security_policy: SecurityPolicy,
    /// Secure channel id
    pub secure_channel_id: UInt32,
    /// Token creation time.
    pub token_created_at: DateTime,
    /// Token lifetime
    pub token_lifetime: UInt32,
    /// Token identifier
    pub token_id: UInt32,
    /// Our nonce generated while handling open secure channel
    pub nonce: Vec<u8>,
    /// Our certificate
    pub cert: Option<X509>,
    /// Our private key
    pub private_key: Option<PKey>,
    /// Symmetric Signing Key, Encrypt Key, IV
    pub keys: Option<(Vec<u8>, AesKey, Vec<u8>)>,
    /// Their nonce provided by open secure channel
    pub their_nonce: Vec<u8>,
    /// Their certificate
    pub their_cert: Option<X509>,
    /// Symmetric Signing Key, Decrypt Key, IV
    pub their_keys: Option<(Vec<u8>, AesKey, Vec<u8>)>,
}

impl SecureChannel {
    /// For testing purposes only
    pub fn new_no_certificate_store() -> SecureChannel {
        SecureChannel {
            security_mode: MessageSecurityMode::None,
            security_policy: SecurityPolicy::None,
            secure_channel_id: 0,
            token_id: 0,
            token_created_at: DateTime::now(),
            token_lifetime: 0,
            nonce: Vec::with_capacity(64),
            cert: None,
            private_key: None,
            keys: None,
            their_nonce: Vec::with_capacity(64),
            their_cert: None,
            their_keys: None,
        }
    }

    pub fn new(certificate_store: Arc<Mutex<CertificateStore>>) -> SecureChannel {
        let (cert, private_key) = {
            let certificate_store = certificate_store.lock().unwrap();
            if let Ok((cert, pkey)) = certificate_store.read_own_cert_and_pkey() {
                (Some(cert), Some(pkey))
            }
            else {
                error!("Cannot read our own certificate and private key. Check paths. Crypto won't work");
                (None, None)
            }
        };
        SecureChannel {
            security_mode: MessageSecurityMode::None,
            security_policy: SecurityPolicy::None,
            secure_channel_id: 0,
            token_id: 0,
            token_created_at: DateTime::now(),
            token_lifetime: 0,
            nonce: Vec::with_capacity(64),
            cert,
            private_key,
            keys: None,
            their_nonce: Vec::with_capacity(64),
            their_cert: None,
            their_keys: None,
        }
    }

    pub fn make_security_header(&self, message_type: MessageChunkType) -> SecurityHeader {
        match message_type {
            MessageChunkType::OpenSecureChannel => {
                SecurityHeader::Asymmetric(AsymmetricSecurityHeader::none())
            }
            _ => {
                SecurityHeader::Symmetric(SymmetricSecurityHeader {
                    token_id: self.token_id,
                })
            }
        }
    }

    /// Creates a nonce for the connection. The nonce should be the same size as the symmetric key
    pub fn create_random_nonce(&mut self) {
        if self.signing_enabled() || self.encryption_enabled() {
            use rand::{self, Rng};
            let mut rng = rand::thread_rng();
            self.nonce = vec![0u8; self.security_policy.symmetric_key_size()];
            rng.fill_bytes(&mut self.nonce);
        } else {
            self.nonce = vec![0u8; 1];
        }
    }

    /// Set their nonce which should be the same as the symmetric key
    pub fn set_their_nonce(&mut self, their_nonce: &ByteString) -> Result<(), StatusCode> {
        if let Some(ref their_nonce) = their_nonce.value {
            if (self.signing_enabled() || self.encryption_enabled()) && their_nonce.len() != self.security_policy.symmetric_key_size() {
                Err(BAD_NONCE_INVALID)
            } else {
                self.their_nonce = their_nonce.to_vec();
                Ok(())
            }
        } else {
            Err(BAD_NONCE_INVALID)
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
    pub fn derive_keys(&mut self) {
        self.keys = Some(self.security_policy.make_secure_channel_keys(&self.nonce, &self.their_nonce));
        debug!("Derived our keys = {:?}", self.keys);
        self.their_keys = Some(self.security_policy.make_secure_channel_keys(&self.their_nonce, &self.nonce));
        debug!("Derived their keys = {:?}", self.their_keys);
    }

    /// Test if the token has expired yet
    pub fn token_has_expired(&self) -> bool {
        let now = DateTime::now().as_chrono();
        let token_expires = self.token_created_at.as_chrono() + chrono::Duration::seconds(self.token_lifetime as i64);
        if now.ge(&token_expires) { true } else { false }
    }

    pub fn symmetric_signature_size(&self) -> usize {
        if self.security_policy != SecurityPolicy::None {
            self.security_policy.symmetric_signature_size()
        } else {
            0
        }
    }

    /// Calculates the signature size for a message depending on the supplied security header
    fn signature_size(&self, security_header: &SecurityHeader) -> usize {
        // Signature size in bytes
        match security_header {
            &SecurityHeader::Asymmetric(ref security_header) => {
                let cert = X509::from_byte_string(&security_header.sender_certificate).unwrap();
                let pkey = cert.public_key().unwrap();
                pkey.bit_length() / 8
            }
            &SecurityHeader::Symmetric(_) => {
                // Signature size comes from policy
                self.security_policy.symmetric_signature_size()
            }
        }
    }

    /// Calculate the padding size
    ///
    /// Padding adds bytes to the body to make it a multiple of the block size so it can be encrypted.
    pub fn calc_chunk_padding(&self, bytes_to_write: usize, security_header: &SecurityHeader, message_chunk_size: usize) -> usize {
        if self.security_policy != SecurityPolicy::None && self.security_mode != MessageSecurityMode::None {
            // Signature size in bytes
            let signature_size = self.signature_size(security_header);

            // Plain text block size comes from policy
            let plain_text_block_size = self.security_policy.plain_block_size();

            // If a message chunk size is specified then we need to calculate the max body size
            let max_body_size = if message_chunk_size != 0 {
                // Cipher text block size comes from policy
                let cipher_text_block_size = self.security_policy.cipher_block_size();
                // Header size include message header and security header
                let header_size = MESSAGE_CHUNK_HEADER_SIZE + security_header.byte_len();
                // Sequence header size is 8 bytes
                let sequence_header_size = SEQUENCE_HEADER_SIZE;

                let f1: f64 = (message_chunk_size - header_size - signature_size - 1) as f64;
                let f2: f64 = cipher_text_block_size as f64;
                plain_text_block_size * ((f1 / f2).floor() as usize) - sequence_header_size
            } else {
                0
            };
            let padding_size = if max_body_size > 0 && bytes_to_write > max_body_size {
                0
            } else {
                plain_text_block_size - ((bytes_to_write + signature_size + 1) % plain_text_block_size)
            };
            debug!("Padding calculated to be {} bytes", padding_size);
            padding_size
        } else {
            0
        }
    }

    pub fn signing_enabled(&self) -> bool {
        self.security_policy != SecurityPolicy::None && self.security_mode == MessageSecurityMode::Sign
    }

    /// Test if encryption is enabled.
    pub fn encryption_enabled(&self) -> bool {
        self.security_policy != SecurityPolicy::None && self.security_mode == MessageSecurityMode::SignAndEncrypt
    }

    pub fn asymmetric_decrypt_and_verify(&self, sender_cert: PKey, receiver_thumbprint: ByteString, src: &[u8], sr: Range<usize>, er: Range<usize>, dst: &mut [u8]) -> Result<(), StatusCode> {
        if self.security_mode == MessageSecurityMode::None {
            panic!("Should not be decrypting or verifying anything with security mode is None");
        }

        // Unlike the symmetric_decrypt_and_verify, this code will ALWAYS decrypt and verify regardless
        // of security policy. This is part of the OpenSecureChannel request on a sign / signencrypt
        // mode connection.

        // The sender_certificate is is the cert used to sign the message, i.e. the client's cert
        //
        // The receiver certificate thumbprint identifies which of our certs was used by the client
        // to encrypt the message. We have to work out from the thumbprint which cert to use

        self.expect_supported_security_policy();

        // There is an expectation that the block is padded so, this is a quick test
        let plaintext_block_size = er.end - er.start;
        if plaintext_block_size % 16 != 0 {
            error!("The plain text block is not padded properly, size = {}", plaintext_block_size);
            return Err(BAD_DECODING_ERROR);
        }

        debug!("Decrypting message with our certificate");

        // Copy security header
        &dst[..er.start].copy_from_slice(&src[..er.start]);

        // Decrypt encrypted portion
        let mut decrypted_tmp = vec![0u8; plaintext_block_size + 16]; // tmp includes +16 for blocksize
        self.asymmetric_decrypt(receiver_thumbprint.as_ref(), &src[er.clone()], &mut decrypted_tmp)?;
        &dst[er.clone()].copy_from_slice(&decrypted_tmp[..plaintext_block_size]);

        // Verify signature (after encrypted portion)
        self.asymmetric_verify_signature(sender_cert, &dst[sr.clone()], &dst[sr.start..])?;

        {
            use debug;
            debug::debug_buffer("Decrypted message", dst);
        }

        // Decrypted and verified into dst
        Ok(())
    }

    fn asymmetric_verify_signature(&self, certificate: PKey, src: &[u8], signature: &[u8]) -> Result<(), StatusCode> {
        // Err(BAD_NOT_IMPLEMENTED)
        // TODO !!!!!
        Ok(())
    }

    fn asymmetric_decrypt(&self, receiver_thumbprint: &[u8], src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
        // Find the thumbprint in our certificate store
        if self.cert.is_none() || self.private_key.is_none() {
            Err(BAD_NO_VALID_CERTIFICATES)
        } else {
            // The thumbprint has to match our cert's thumbprint, otherwise something has gone wrong
            let thumbprint = self.cert.as_ref().unwrap().thumbprint();
            if &thumbprint[..] != receiver_thumbprint {
                Err(BAD_NO_VALID_CERTIFICATES)
            } else {
                // decrypt data using our private key
                let private_key = self.private_key.as_ref().unwrap();
                let rsa = private_key.value.rsa().unwrap();
                rsa.private_decrypt(src, dst, PKCS1_PADDING).unwrap();
                Ok(())
            }
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
    pub fn symmetric_encrypt_and_sign(&self, src: &[u8], sr: Range<usize>, er: Range<usize>, dst: &mut [u8]) -> Result<(), StatusCode> {
        match self.security_mode {
            MessageSecurityMode::None => {
                debug!("encrypt_and_sign is doing nothing because security mode == None");
                // Just copy data to out
                dst.copy_from_slice(src);
                Ok(())
            }
            MessageSecurityMode::Sign => {
                debug!("encrypt_and_sign security mode == Sign");
                self.expect_supported_security_policy();
                let signature_len = src.len() - sr.end;
                let mut signature = vec![0u8; signature_len];
                debug!("signature len = {}", signature_len);
                // Sign the message header, security header, sequence header, body, padding
                self.symmetric_sign(&src[sr.clone()], &mut signature)?;
                &dst[sr.clone()].copy_from_slice(&src[sr.clone()]);
                debug!("Signature = {:?}", signature);
                &dst[sr.end..].copy_from_slice(&signature);
                Ok(())
            }
            MessageSecurityMode::SignAndEncrypt => {
                debug!("encrypt_and_sign security mode == SignAndEncrypt");
                self.expect_supported_security_policy();

                // There is an expectation that the block is padded so, this is a quick test
                let plaintext_block_size = er.end - er.start;
                if plaintext_block_size % 16 != 0 {
                    error!("The plain text block is not padded properly, size = {}", plaintext_block_size);
                    return Err(BAD_DECODING_ERROR);
                }
                let mut dst_tmp = vec![0u8; dst.len() + 16]; // tmp includes +16 for blocksize
                let signature_len = src.len() - sr.end;
                debug!("signature len = {}", signature_len);
                let mut signature = vec![0u8; signature_len];
                // Sign the message header, security header, sequence header, body, padding
                self.symmetric_sign(&src[sr.clone()], &mut signature)?;
                &dst_tmp[sr.clone()].copy_from_slice(&src[sr.clone()]);
                &dst_tmp[sr.end..].copy_from_slice(&signature);

                // Encrypt the sequence header, payload, signature
                self.symmetric_encrypt(&dst_tmp[er.clone()], &mut dst[er.clone()])?;
                // Copy the message header / security header
                &dst[..er.start].copy_from_slice(&dst_tmp[..er.start]);

                Ok(())
            }
            MessageSecurityMode::Invalid => {
                panic!("Message security mode is invalid");
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
    pub fn symmetric_decrypt_and_verify(&self, src: &[u8], sr: Range<usize>, er: Range<usize>, dst: &mut [u8]) -> Result<(), StatusCode> {
        match self.security_mode {
            MessageSecurityMode::None => {
                // Just copy everything from src to dst
                let all = ..src.len();
                &dst[all].copy_from_slice(&src[all]);
                Ok(())
            }
            MessageSecurityMode::Sign => {
                self.expect_supported_security_policy();
                // Copy everything
                let all = ..src.len();
                debug!("copying from slice {:?}", all);
                &dst[all].copy_from_slice(&src[all]);
                // Verify signature
                debug!("Verifying range from {:?} to signature {}..", sr, sr.end);
                self.symmetric_verify_signature(&dst[sr.clone()], &dst[sr.end..])?;
                Ok(())
            }
            MessageSecurityMode::SignAndEncrypt => {
                self.expect_supported_security_policy();

                // There is an expectation that the block is padded so, this is a quick test
                let plaintext_block_size = er.end - er.start;
                if plaintext_block_size % 16 != 0 {
                    error!("The plain text block is not padded properly, size = {}", plaintext_block_size);
                    return Err(BAD_DECODING_ERROR);
                }

                // Copy security header
                &dst[..er.start].copy_from_slice(&src[..er.start]);

                // Decrypt encrypted portion
                let mut decrypted_tmp = vec![0u8; plaintext_block_size + 16]; // tmp includes +16 for blocksize
                self.symmetric_decrypt(&src[er.clone()], &mut decrypted_tmp)?;
                &dst[er.clone()].copy_from_slice(&decrypted_tmp[..plaintext_block_size]);

                // Verify signature (after encrypted portion)
                self.symmetric_verify_signature(&dst[sr.clone()], &dst[sr.start..])?;
                Ok(())
            }
            MessageSecurityMode::Invalid => {
                // Use the security policy to decrypt the block using the token
                panic!("Message security mode is invalid");
            }
        }
    }

    /// Sign the following block
    fn symmetric_sign(&self, src: &[u8], signature: &mut [u8]) -> Result<(), StatusCode> {
        debug!("Producing signature for {} bytes of data into signature of {} bytes", src.len(), signature.len());
        let key = &(self.keys.as_ref().unwrap()).0;
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15 => {
                // HMAC SHA-1
                hash::hmac_sha1(key, src, signature)
            }
            SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                // HMAC SHA-256                
                hash::hmac_sha256(key, src, signature)
            }
            _ => {
                panic!("Unsupported policy")
            }
        }
    }

    /// Verify their signature
    fn symmetric_verify_signature(&self, src: &[u8], signature: &[u8]) -> Result<(), StatusCode> {
        let key = &(self.their_keys.as_ref().unwrap()).0;
        // Verify the signature using SHA-1 / SHA-256 HMAC
        let verified = match self.security_policy {
            SecurityPolicy::Basic128Rsa15 => {
                // HMAC SHA-1
                hash::verify_hmac_sha1(key, src, signature)
            }
            SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                // HMAC SHA-256                
                hash::verify_hmac_sha256(key, src, signature)
            }
            _ => {
                panic!("Unsupported policy")
            }
        };
        if verified {
            Ok(())
        } else {
            error!("Signature invalid {:?}", signature);
            Err(BAD_APPLICATION_SIGNATURE_INVALID)
        }
    }

    /// Encrypt the data
    fn symmetric_encrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
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
    fn symmetric_decrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), StatusCode> {
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

    // Panic code which requires a policy
    fn expect_supported_security_policy(&self) {
        match self.security_policy {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {}
            _ => {
                panic!("Unsupported security policy");
            }
        }
    }
}
