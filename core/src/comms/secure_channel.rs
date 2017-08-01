use std::sync::{Arc, Mutex};
use std::ops::Range;

use chrono;

use opcua_types::*;

use crypto::SecurityPolicy;
use crypto::CertificateStore;
use crypto::types::*;

use comms::{SecurityHeader, SymmetricSecurityHeader, AsymmetricSecurityHeader};
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
    /// Their nonce provided by open secure channel
    pub their_nonce: Vec<u8>,
    /// Their certificate
    pub their_cert: Option<X509>,
    /// Symmetric Signing Key, Encrypt Key, IV
    pub sending_keys: Option<(Vec<u8>, AesKey, Vec<u8>)>,
    /// Symmetric Signing Key, Decrypt Key, IV
    pub receiving_keys: Option<(Vec<u8>, AesKey, Vec<u8>)>,
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
            their_nonce: Vec::with_capacity(64),
            their_cert: None,
            sending_keys: None,
            receiving_keys: None,
        }
    }

    pub fn new(certificate_store: Arc<Mutex<CertificateStore>>) -> SecureChannel {
        let (cert, private_key) = {
            let certificate_store = certificate_store.lock().unwrap();
            if let Ok((cert, pkey)) = certificate_store.read_own_cert_and_pkey() {
                (Some(cert), Some(pkey))
            } else {
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
            sending_keys: None,
            their_nonce: Vec::with_capacity(64),
            their_cert: None,
            receiving_keys: None,
        }
    }

    pub fn make_security_header(&self, message_type: MessageChunkType) -> SecurityHeader {
        match message_type {
            MessageChunkType::OpenSecureChannel => {
                let asymmetric_security_header = if self.security_policy == SecurityPolicy::None {
                    AsymmetricSecurityHeader::none()
                } else {
                    let receiver_certificate_thumbprint = self.their_cert.as_ref().unwrap().thumbprint().as_byte_string();
                    AsymmetricSecurityHeader::new(self.security_policy, self.cert.as_ref().unwrap(), receiver_certificate_thumbprint)
                };
                SecurityHeader::Asymmetric(asymmetric_security_header)
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
        self.sending_keys = Some(self.security_policy.make_secure_channel_keys(&self.nonce, &self.their_nonce));
        debug!("Derived our keys = {:?}", self.sending_keys);
        self.receiving_keys = Some(self.security_policy.make_secure_channel_keys(&self.their_nonce, &self.nonce));
        debug!("Derived their keys = {:?}", self.receiving_keys);
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
    pub fn calc_chunk_padding(&self, bytes_to_write: usize, security_header: &SecurityHeader) -> usize {
        if self.security_policy != SecurityPolicy::None && self.security_mode != MessageSecurityMode::None {
            // Signature size in bytes
            let signature_size = self.signature_size(security_header);
            let padding_size = match security_header {
                &SecurityHeader::Asymmetric(_) => {
                    if bytes_to_write < signature_size {
                        signature_size - bytes_to_write
                    } else {
                        bytes_to_write
                    }
                }
                &SecurityHeader::Symmetric(_) => {
                    // Plain text block size comes from policy
                    let plain_text_block_size = self.security_policy.plain_block_size();

                    // PaddingSize = PlainTextBlockSize –
                    // ((BytesToWrite + SignatureSize + 1) % PlainTextBlockSize);
                    // Note +2 for signature size > 255

                    let mut plain_text_size = bytes_to_write;
                    plain_text_size += self.security_policy.symmetric_signature_size();
                    if plain_text_block_size > 255 {
                        plain_text_size += 1;
                    }

                    debug!("bytes to write = {}, plain block size = {}, signature size = {}, plain text size = {}", bytes_to_write, plain_text_block_size, self.security_policy.symmetric_signature_size(), plain_text_size);

                    if plain_text_size % plain_text_block_size != 0 {
                        plain_text_block_size - (plain_text_size % plain_text_block_size)
                    } else {
                        0
                    }
                }
            };
            debug!("Padding = {}", padding_size);
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

    pub fn asymmetric_decrypt_and_verify(&mut self, security_policy: SecurityPolicy, verification_key: &PKey, receiver_thumbprint: ByteString, src: &[u8], encrypted_range: Range<usize>, dst: &mut [u8]) -> Result<usize, StatusCode> {
        // Asymmetric encrypt requires the caller supply the security policy
        match security_policy {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {}
            _ => {
                return Err(BAD_SECURITY_POLICY_REJECTED);
            }
        }
        self.security_policy = security_policy;

        // Unlike the symmetric_decrypt_and_verify, this code will ALWAYS decrypt and verify regardless
        // of security mode. This is part of the OpenSecureChannel request on a sign / signencrypt
        // mode connection.

        // The sender_certificate is is the cert used to sign the message, i.e. the client's cert
        //
        // The receiver certificate thumbprint identifies which of our certs was used by the client
        // to encrypt the message. We have to work out from the thumbprint which cert to use

        let our_cert = self.cert.as_ref().unwrap();
        let our_thumbprint = our_cert.thumbprint();
        if &our_thumbprint.value[..] != receiver_thumbprint.as_ref() {
            error!("Supplied thumbprint does not match application certificate's thumbprint");
            Err(BAD_NO_VALID_CERTIFICATES)
        } else {
            // Copy message, security header
            &dst[..encrypted_range.start].copy_from_slice(&src[..encrypted_range.start]);

            // Decrypt and copy encrypted block
            // Note that the unencrypted size can be less than the encrypted size due to removal
            // of padding, so the ranges that were supplied to this function must be offset to compensate.
            let encrypted_size = encrypted_range.end - encrypted_range.start;
            debug!("Decrypting message with our certificate range {:?}", encrypted_range);
            let mut decrypted_tmp = vec![0u8; encrypted_size];

            let private_key = self.private_key.as_ref().unwrap();
            let private_key_size = private_key.bit_length() / 8;
            let decrypted_size = security_policy.asymmetric_decrypt(private_key, &src[encrypted_range.clone()], &mut decrypted_tmp)?;
            debug!("Decrypted bytes = {} compared to encrypted range {}", decrypted_size, encrypted_size);

            {
                use debug;
                debug::debug_buffer("Decrypted data = ", &decrypted_tmp[0..decrypted_size])
            }

            // The signed range is from 0 to the end of the plaintext except for key size
            let signed_range = 0..(encrypted_range.start + decrypted_size - private_key_size);

            // The signature range is beyond the signed range and is
            let signature_range = signed_range.end..(signed_range.end + private_key_size);

            // Copy the bytes to dst
            &dst[encrypted_range.start..signature_range.end].copy_from_slice(&decrypted_tmp[0..decrypted_size]);

            // Verify signature (contained encrypted portion) using verification key
            debug!("Verifying signature range {:?} with signature at {:?}", signed_range, signature_range);
            security_policy.asymmetric_verify_signature(verification_key, &dst[signed_range.clone()], &dst[signature_range.clone()])?;

            // Decrypted and verified into dst
            Ok(signature_range.start)
        }
    }

    /// Use the security policy to asymmetric encrypt and sign the specified chunk of data
    pub fn asymmetric_encrypt_and_sign(&self, security_policy: SecurityPolicy, src: &[u8], encrypted_range: Range<usize>, dst: &mut [u8]) -> Result<usize, StatusCode> {
        let signing_key = self.private_key.as_ref().unwrap();
        let signing_key_size = signing_key.bit_length() / 8;

        let signed_range = 0..(encrypted_range.end - signing_key_size);
        let signature_range = (encrypted_range.end - signing_key_size)..encrypted_range.end;

        debug!("Encrypted range = {:?}, signed range = {:?}, signature range = {:?}", encrypted_range, signed_range, signature_range);

        debug!("signature len = {}", signing_key_size);
        let mut signature = vec![0u8; signing_key_size];

        // Sign the message header, security header, sequence header, body, padding
        security_policy.asymmetric_sign(&signing_key, &src[signed_range.clone()], &mut signature)?;

        let mut tmp = vec![0u8; dst.len()];
        &tmp[signed_range.clone()].copy_from_slice(&src[signed_range.clone()]);
        &tmp[signature_range.clone()].copy_from_slice(&signature);

        // Copy the unecryped message header / security header portion to dst
        &dst[..encrypted_range.start].copy_from_slice(&tmp[..encrypted_range.start]);

        // Encrypt the sequence header, payload, signature portion into dst
        let encryption_key = self.their_cert.as_ref().unwrap().public_key()?;
        let encrypted_size = security_policy.asymmetric_encrypt(&encryption_key, &tmp[encrypted_range.clone()], &mut dst[encrypted_range.start..])?;

        let encrypted_size = encrypted_range.start + encrypted_size;

        {
            use debug;
            debug!("Encrypted size in bytes = {} compared to encrypted range {:?}", encrypted_size, encrypted_range);
            debug::debug_buffer("Start of buffer", &dst[0..64]);
            debug::debug_buffer("End of buffer", &dst[(encrypted_size - 64)..]);
        }

        Ok(encrypted_size)
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
    pub fn symmetric_encrypt_and_sign(&self, src: &[u8], signed_range: Range<usize>, encrypted_range: Range<usize>, dst: &mut [u8]) -> Result<usize, StatusCode> {
        let encrypted_size = match self.security_mode {
            MessageSecurityMode::None => {
                debug!("encrypt_and_sign is doing nothing because security mode == None");
                // Just copy data to out
                dst.copy_from_slice(src);

                src.len()
            }
            MessageSecurityMode::Sign => {
                debug!("encrypt_and_sign security mode == Sign");
                self.expect_supported_security_policy();
                self.symmetric_sign(src, signed_range, dst)?
            }
            MessageSecurityMode::SignAndEncrypt => {
                debug!("encrypt_and_sign security mode == SignAndEncrypt");
                self.expect_supported_security_policy();

                let mut dst_tmp = vec![0u8; dst.len() + 16]; // tmp includes +16 for blocksize

                // Sign the block
                let _ = self.symmetric_sign(src, signed_range, &mut dst_tmp)?;

                // Encrypt the sequence header, payload, signature
                let keys = self.sending_keys.as_ref().unwrap();
                let key = &keys.1;
                let iv = &keys.2;
                let encrypted_size = self.security_policy.symmetric_encrypt(key, iv, &dst_tmp[encrypted_range.clone()], &mut dst[encrypted_range.start..(encrypted_range.end + 16)])?;
                // Copy the message header / security header
                &dst[..encrypted_range.start].copy_from_slice(&dst_tmp[..encrypted_range.start]);

                encrypted_range.start + encrypted_size
            }
            MessageSecurityMode::Invalid => {
                panic!("Message security mode is invalid");
            }
        };
        Ok(encrypted_size)
    }

    fn symmetric_sign(&self, src: &[u8], signed_range: Range<usize>, dst: &mut [u8]) -> Result<usize, StatusCode> {
        let signature_size = self.security_policy.symmetric_signature_size();
        let mut signature = vec![0u8; signature_size];
        let signature_range = signed_range.end..(signed_range.end + signature_size);
        debug!("signed_range = {:?}, signature range = {:?}, signature len = {}", signed_range, signature_range, signature_size);

        // Sign the message header, security header, sequence header, body, padding
        let key = &(self.sending_keys.as_ref().unwrap()).0;
        self.security_policy.symmetric_sign(key, &src[signed_range.clone()], &mut signature)?;

        debug!("Signature = {:?}", signature);

        // Copy the signed portion and the signature to the destination
        &dst[signed_range.clone()].copy_from_slice(&src[signed_range.clone()]);
        &dst[signature_range.clone()].copy_from_slice(&signature);

        Ok(signature_range.end)
    }

    /// Decrypts and verifies data.
    ///
    /// Returns the size of the decrypted data
    ///
    /// S - Message Header
    /// S - Security Header
    /// S - Sequence Header - E
    /// S - Body            - E
    /// S - Padding         - E
    ///     Signature       - E
    pub fn symmetric_decrypt_and_verify(&self, src: &[u8], signed_range: Range<usize>, encrypted_range: Range<usize>, dst: &mut [u8]) -> Result<usize, StatusCode> {
        match self.security_mode {
            MessageSecurityMode::None => {
                // Just copy everything from src to dst
                let all = ..;
                &dst[all].copy_from_slice(&src[all]);
                Ok(src.len())
            }
            MessageSecurityMode::Sign => {
                self.expect_supported_security_policy();
                // Copy everything
                let all = ..src.len();
                debug!("copying from slice {:?}", all);
                &dst[all].copy_from_slice(&src[all]);
                // Verify signature
                debug!("Verifying range from {:?} to signature {}..", signed_range, signed_range.end);
                let key = &(self.receiving_keys.as_ref().unwrap()).0;
                self.security_policy.symmetric_verify_signature(key, &dst[signed_range.clone()], &dst[signed_range.end..])?;

                Ok(encrypted_range.end)
            }
            MessageSecurityMode::SignAndEncrypt => {
                self.expect_supported_security_policy();

                // There is an expectation that the block is padded so, this is a quick test
                let ciphertext_size = encrypted_range.end - encrypted_range.start;
                //                if ciphertext_size % 16 != 0 {
                //                    error!("The cipher text size is not padded properly, size = {}", ciphertext_size);
                //                    return Err(BAD_UNEXPECTED_ERROR);
                //                }

                // Copy security header
                &dst[..encrypted_range.start].copy_from_slice(&src[..encrypted_range.start]);

                // Decrypt encrypted portion
                let mut decrypted_tmp = vec![0u8; ciphertext_size + 16]; // tmp includes +16 for blocksize
                let keys = self.receiving_keys.as_ref().unwrap();
                let key = &keys.1;
                let iv = &keys.2;

                debug!("Secure decrypt called with encrypted range {:?}", encrypted_range);
                let decrypted_size = self.security_policy.symmetric_decrypt(key, iv, &src[encrypted_range.clone()], &mut decrypted_tmp[..])?;

                let encrypted_range = encrypted_range.start..(encrypted_range.start + decrypted_size);
                &dst[encrypted_range.clone()].copy_from_slice(&decrypted_tmp[..decrypted_size]);

                // Verify signature (after encrypted portion)
                let signature_range = (encrypted_range.end - self.security_policy.symmetric_signature_size())..encrypted_range.end;
                let key = &(self.sending_keys.as_ref().unwrap()).0;
                self.security_policy.symmetric_verify_signature(key, &dst[signed_range.clone()], &dst[signature_range])?;
                Ok(encrypted_range.end)
            }
            MessageSecurityMode::Invalid => {
                // Use the security policy to decrypt the block using the token
                panic!("Message security mode is invalid");
            }
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
