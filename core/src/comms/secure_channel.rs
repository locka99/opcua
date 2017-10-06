use std::sync::{Arc, Mutex};
use std::ops::Range;
use std::io::{Cursor, Write};

use chrono;

use opcua_types::*;

use crypto::SecurityPolicy;
use crypto::CertificateStore;
use crypto::x509::X509;
use crypto::aeskey::AesKey;
use crypto::pkey::PKey;

use comms::security_header::{SecurityHeader, SymmetricSecurityHeader, AsymmetricSecurityHeader};
use comms::message_chunk::{MessageChunkHeader, MessageChunkType, MessageChunk};

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
    /// Our certificate
    pub cert: Option<X509>,
    /// Our private key
    pub private_key: Option<PKey>,
    /// Their certificate
    pub their_cert: Option<X509>,
    /// Our nonce generated while handling open secure channel
    pub server_nonce: Vec<u8>,
    /// Their nonce provided by open secure channel
    pub client_nonce: Vec<u8>,
    /// Client (i.e. other end's set of keys) Symmetric Signing Key, Encrypt Key, IV
    pub client_keys: Option<(Vec<u8>, AesKey, Vec<u8>)>,
    /// Server (i.e. our end's set of keys) Symmetric Signing Key, Decrypt Key, IV
    pub server_keys: Option<(Vec<u8>, AesKey, Vec<u8>)>,
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
            server_nonce: Vec::new(),
            client_nonce: Vec::new(),
            cert: None,
            private_key: None,
            their_cert: None,
            server_keys: None,
            client_keys: None,
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
            client_nonce: Vec::new(),
            server_nonce: Vec::new(),
            cert,
            private_key,
            their_cert: None,
            server_keys: None,
            client_keys: None,
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
        if self.security_policy != SecurityPolicy::None && (self.security_mode == MessageSecurityMode::Sign || self.security_mode == MessageSecurityMode::SignAndEncrypt) {
            use rand::{self, Rng};
            let mut rng = rand::thread_rng();
            self.server_nonce = vec![0u8; self.security_policy.symmetric_key_size()];
            rng.fill_bytes(&mut self.server_nonce);
        } else {
            self.server_nonce = vec![0u8; 1];
        }
    }

    /// Set their nonce which should be the same as the symmetric key
    pub fn set_remote_nonce(&mut self, remote_nonce: &ByteString) -> Result<(), StatusCode> {
        if self.security_policy != SecurityPolicy::None && (self.security_mode == MessageSecurityMode::Sign || self.security_mode == MessageSecurityMode::SignAndEncrypt) {
            if let Some(ref remote_nonce) = remote_nonce.value {
                if remote_nonce.len() != self.security_policy.symmetric_key_size() {
                    return Err(BAD_NONCE_INVALID);
                }
                self.client_nonce = remote_nonce.to_vec();
                Ok(())
            } else {
                Err(BAD_NONCE_INVALID)
            }
        } else {
            Ok(())
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
        self.client_keys = Some(self.security_policy.make_secure_channel_keys(&self.server_nonce, &self.client_nonce));
        self.server_keys = Some(self.security_policy.make_secure_channel_keys(&self.client_nonce, &self.server_nonce));
        trace!("Remote nonce = {:?}", self.client_nonce);
        trace!("Local nonce = {:?}", self.server_nonce);
        trace!("Derived remote keys = {:?}", self.client_keys);
        trace!("Derived local keys = {:?}", self.server_keys);
    }

    /// Test if the token has expired yet
    pub fn token_has_expired(&self) -> bool {
        let now: chrono::DateTime<chrono::UTC> = DateTime::now().into();
        let token_created_at: chrono::DateTime<chrono::UTC> = self.token_created_at.clone().into();
        let token_expires = token_created_at + chrono::Duration::seconds(self.token_lifetime as i64);
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
    pub fn signature_size(&self, security_header: &SecurityHeader) -> usize {
        // Signature size in bytes
        match *security_header {
            SecurityHeader::Asymmetric(ref security_header) => {
                if security_header.sender_certificate.is_null() {
                    0
                } else {
                    let cert = X509::from_byte_string(&security_header.sender_certificate).unwrap();
                    let pkey = cert.public_key().unwrap();
                    pkey.size()
                }
            }
            SecurityHeader::Symmetric(_) => {
                // Signature size comes from policy
                self.security_policy.symmetric_signature_size()
            }
        }
    }

    // Extra padding required for keysize > 2048 bits (256 bytes)
    fn minimum_padding(signature_size: usize) -> usize {
        if signature_size > 256 { 2 } else { 1 }
    }

    /// Calculate the padding size
    ///
    /// Padding adds bytes to the body to make it a multiple of the block size so it can be encrypted.
    pub fn padding_size(&self, security_header: &SecurityHeader, body_size: usize, signature_size: usize) -> usize {
        if self.security_policy != SecurityPolicy::None && self.security_mode != MessageSecurityMode::None {
            // Signature size in bytes
            let plain_text_block_size = match *security_header {
                SecurityHeader::Asymmetric(ref security_header) => {
                    if !security_header.sender_certificate.is_null() {
                        let x509 = X509::from_byte_string(&security_header.sender_certificate).unwrap();
                        x509.public_key().unwrap().size()
                    } else {
                        0
                    }
                }
                SecurityHeader::Symmetric(_) => {
                    // Plain text block size comes from policy
                    self.security_policy.plain_block_size()
                }
            };

            // PaddingSize = PlainTextBlockSize – ((BytesToWrite + SignatureSize + 1) % PlainTextBlockSize);

            let minimum_padding = Self::minimum_padding(signature_size);

            let mut encrypt_size = 0;
            encrypt_size += 8; // sequence header
            encrypt_size += body_size;
            encrypt_size += signature_size;
            encrypt_size += minimum_padding;

            let padding_size = if encrypt_size % plain_text_block_size != 0 {
                plain_text_block_size - (encrypt_size % plain_text_block_size)
            } else {
                0
            };
            trace!("sequence_header(8) + body({}) + signature ({}) = plain text size = {} / with padding {} = {}", body_size, signature_size, encrypt_size, padding_size, encrypt_size + padding_size);
            minimum_padding + padding_size
        } else {
            0
        }
    }

    // Takes an unpadded message chunk and adds padding as well as space to the end to accomodate a signature.
    // Also modifies the message size to include the new padding/signature
    fn add_space_for_padding_and_signature(&self, message_chunk: &MessageChunk) -> Result<Vec<u8>, StatusCode> {
        let chunk_info = message_chunk.chunk_info(self)?;
        let data = &message_chunk.data[..];

        let security_header = chunk_info.security_header;

        let buffer = Vec::with_capacity(message_chunk.data.len() + 4096);
        let mut stream = Cursor::new(buffer);

        // First off just write out the src to the buffer. The message header, security header, sequence header and payload
        let _ = stream.write(&data[..]);

        // Signature size (if required)
        let signature_size = self.signature_size(&security_header);

        // Write padding
        let body_size = chunk_info.body_length;

        let padding_size = self.padding_size(&security_header, body_size, signature_size);
        if padding_size > 0 {
            // A number of bytes are written out equal to the padding size.
            // Each byte is the padding size. So if padding size is 15 then
            // there will be 15 bytes all with the value 15
            let minimum_padding = Self::minimum_padding(signature_size);
            if minimum_padding == 1 {
                let padding_byte = ((padding_size - 1) & 0xff) as u8;
                for _ in 0..padding_size {
                    write_u8(&mut stream, padding_byte)?;
                }
            } else if minimum_padding == 2 {
                // Padding and then extra padding
                let padding_byte = ((padding_size - 2) & 0xff) as u8;
                for _ in 0..padding_size {
                    write_u8(&mut stream, padding_byte)?;
                }
                write_u8(&mut stream, ((padding_size - 2) >> 8) as u8)?;
            }
        }

        // Write zeros for the signature
        for _ in 0..signature_size {
            write_u8(&mut stream, 0u8)?;
        }

        let mut message_size = data.len();
        message_size += padding_size;
        message_size += signature_size;

        // Update message header to reflect size with padding + signature
        Self::update_message_size_and_truncate(stream.into_inner(), message_size)
    }

    fn update_message_size(data: &mut [u8], message_size: usize) -> Result<(), StatusCode> {
        // Read and rewrite the message_size in the header
        let mut stream = Cursor::new(data);
        let mut message_header = MessageChunkHeader::decode(&mut stream)?;
        stream.set_position(0);
        let old_message_size = message_header.message_size;
        message_header.message_size = message_size as UInt32;
        message_header.encode(&mut stream)?;
        trace!("Message header message size being modified from {} to {}", old_message_size, message_size);
        Ok(())
    }

    // Truncates a vec and writes the message size
    pub fn update_message_size_and_truncate(mut data: Vec<u8>, message_size: usize) -> Result<Vec<u8>, StatusCode> {
        Self::update_message_size(&mut data[..], message_size)?;
        // Truncate vector to the size
        data.truncate(message_size);
        Ok(data)
    }

    fn log_crypto_data(message: &str, data: &[u8]) {
        use debug;
        debug::log_buffer(message, data);
    }

    /// Applies security to a message chunk and yields a encrypted/signed block to be streamed
    pub fn apply_security(&self, message_chunk: &MessageChunk, dst: &mut [u8]) -> Result<usize, StatusCode> {
        let size = if self.security_policy != SecurityPolicy::None && (self.security_mode == MessageSecurityMode::Sign || self.security_mode == MessageSecurityMode::SignAndEncrypt) {
            let chunk_info = message_chunk.chunk_info(self)?;

            // S - Message Header
            // S - Security Header
            // S - Sequence Header - E
            // S - Body            - E
            // S - Padding         - E
            //     Signature       - E

            let data = self.add_space_for_padding_and_signature(message_chunk)?;
            Self::log_crypto_data("Chunk before padding", &message_chunk.data[..]);
            Self::log_crypto_data("Chunk after padding", &data[..]);

            // Encrypted range is from the sequence header to the end
            let encrypted_range = chunk_info.sequence_header_offset..data.len();

            // Encrypt and sign - open secure channel
            let encrypted_size = if message_chunk.is_open_secure_channel() {
                self.asymmetric_sign_and_encrypt(self.security_policy, &data, encrypted_range, dst)?
            } else {
                // Symmetric encrypt and sign
                let signed_range = 0..(data.len() - self.security_policy.symmetric_signature_size());
                self.symmetric_sign_and_encrypt(&data, signed_range, encrypted_range, dst)?
            };

            Self::log_crypto_data("Chunk after encryption", &dst[..encrypted_size]);

            encrypted_size
        } else {
            let size = message_chunk.data.len();
            dst[..size].copy_from_slice(&message_chunk.data[..]);
            size
        };
        Ok(size)
    }

    /// Decrypts and verifies the body data if the mode / policy requires it
    pub fn verify_and_remove_security(&mut self, src: &[u8]) -> Result<MessageChunk, StatusCode> {
        self.verify_and_remove_security_forensic(src, None)
    }

    /// Decrypts and verifies the body data if the mode / policy requires it
    ///
    /// Note, that normally we do not have "their" key but for testing purposes and forensics, we
    /// might have the key
    pub fn verify_and_remove_security_forensic(&mut self, src: &[u8], their_key: Option<PKey>) -> Result<MessageChunk, StatusCode> {
        // Get message & security header from data
        let (message_header, security_header, encrypted_data_offset) = {
            let mut stream = Cursor::new(&src);
            let message_header = MessageChunkHeader::decode(&mut stream)?;
            let security_header = if message_header.message_type.is_open_secure_channel() {
                SecurityHeader::Asymmetric(AsymmetricSecurityHeader::decode(&mut stream)?)
            } else {
                SecurityHeader::Symmetric(SymmetricSecurityHeader::decode(&mut stream)?)
            };
            let encrypted_data_offset = stream.position() as usize;
            (message_header, security_header, encrypted_data_offset)
        };

        let message_size = message_header.message_size as usize;
        if message_size != src.len() {
            error!("The message size {} is not the same as the supplied buffer {}", message_size, src.len());
            return Err(BAD_UNEXPECTED_ERROR);
        }

        // S - Message Header
        // S - Security Header
        // S - Sequence Header - E
        // S - Body            - E
        // S - Padding         - E
        //     Signature       - E
        let data = if message_header.message_type.is_open_secure_channel() {
            // The OpenSecureChannel is the first thing we receive so we must examine
            // the security policy and use it to determine if the packet must be decrypted.
            let encrypted_range = encrypted_data_offset..message_size;

            trace!("Decrypting OpenSecureChannel");

            let security_header = match security_header {
                SecurityHeader::Asymmetric(security_header) => security_header,
                _ => {
                    panic!();
                }
            };

            // The security policy dictates the encryption / signature algorithms used by the request
            let security_policy = SecurityPolicy::from_uri(security_header.security_policy_uri.as_ref());
            match security_policy {
                SecurityPolicy::Unknown => {
                    return Err(BAD_SECURITY_POLICY_REJECTED);
                }
                SecurityPolicy::None => {
                    // Nothing to do
                    return Ok(MessageChunk { data: src.to_vec() });
                }
                _ => {}
            }
            self.security_policy = security_policy;

            // Asymmetric decrypt and verify

            // The OpenSecureChannel Messages are signed and encrypted if the SecurityMode is not None
            // (even if the SecurityMode is SignOnly)

            // An OpenSecureChannelRequest uses Asymmetric encryption - decrypt using the server's private
            // key, verify signature with client's public key.

            // This code doesn't *care* if the cert is trusted, merely that it was used to sign the message
            if security_header.sender_certificate.is_null() {
                error!("Sender certificate is NULL!!!");
                // TODO return
            }

            let sender_certificate_len = security_header.sender_certificate.value.as_ref().unwrap().len();
            trace!("Sender certificate byte length = {}", sender_certificate_len);
            let sender_certificate = X509::from_byte_string(&security_header.sender_certificate)?;

            let verification_key = sender_certificate.public_key()?;
            let receiver_thumbprint = security_header.receiver_certificate_thumbprint;
            trace!("Receiver thumbprint = {:?}", receiver_thumbprint);

            let mut decrypted_data = vec![0u8; message_size];
            let decrypted_size = self.asymmetric_decrypt_and_verify(security_policy, &verification_key, receiver_thumbprint, src, encrypted_range, their_key, &mut decrypted_data)?;

            Self::update_message_size_and_truncate(decrypted_data, decrypted_size)?
        } else if self.security_policy != SecurityPolicy::None && (self.security_mode == MessageSecurityMode::Sign || self.security_mode == MessageSecurityMode::SignAndEncrypt) {
            // Symmetric decrypt and verify
            let signature_size = self.security_policy.symmetric_signature_size();
            let encrypted_range = encrypted_data_offset..message_size;
            let signed_range = 0..(message_size - signature_size);
            debug!("Decrypting block with signature info {:?} and encrypt info {:?}", signed_range, encrypted_range);

            let mut decrypted_data = vec![0u8; message_size];
            let decrypted_size = self.symmetric_decrypt_and_verify(src, signed_range, encrypted_range, &mut decrypted_data)?;

            // Now we need to strip off signature
            Self::update_message_size_and_truncate(decrypted_data, decrypted_size - signature_size)?
        } else {
            src.to_vec()
        };

        Ok(MessageChunk { data })
    }

    /// Use the security policy to asymmetric encrypt and sign the specified chunk of data
    fn asymmetric_sign_and_encrypt(&self, security_policy: SecurityPolicy, src: &[u8], encrypted_range: Range<usize>, dst: &mut [u8]) -> Result<usize, StatusCode> {
        let signing_key = self.private_key.as_ref().unwrap();
        let signing_key_size = signing_key.size();

        let signed_range = 0..(encrypted_range.end - signing_key_size);
        let signature_range = (encrypted_range.end - signing_key_size)..encrypted_range.end;

        trace!("Encrypted range = {:?}, signed range = {:?}, signature range = {:?}", encrypted_range, signed_range, signature_range);

        trace!("signature len = {}", signing_key_size);
        let mut signature = vec![0u8; signing_key_size];
        let encryption_key = self.their_cert.as_ref().unwrap().public_key()?;

        let mut tmp = vec![0u8; encrypted_range.end];
        tmp[signed_range.clone()].copy_from_slice(&src[signed_range.clone()]);

        // Encryption will change the size of the chunk. Since we sign before encrypting, we need to
        // compute that size and change the message header to be that new size
        let encrypted_block_size = {
            let plain_text_size = encrypted_range.end - encrypted_range.start;
            let encrypted_block_size = encryption_key.calculate_cipher_text_size(security_policy.padding(), plain_text_size);
            trace!("plain_text_size = {}, encrypted_block_size = {}", plain_text_size, encrypted_block_size);
            encrypted_block_size
        };
        Self::update_message_size(&mut tmp[..], encrypted_range.start + encrypted_block_size)?;

        // Sign the message header, security header, sequence header, body, padding
        security_policy.asymmetric_sign(&signing_key, &tmp[signed_range.clone()], &mut signature)?;
        tmp[signature_range.clone()].copy_from_slice(&signature);
        assert_eq!(encrypted_range.end, signature_range.end);

        Self::log_crypto_data("Chunk after signing", &tmp[..signature_range.end]);

        // Copy the unecrypted message header / security header portion to dst
        dst[..encrypted_range.start].copy_from_slice(&tmp[..encrypted_range.start]);

        // Encrypt the sequence header, payload, signature portion into dst
        let encrypted_size = security_policy.asymmetric_encrypt(&encryption_key, &tmp[encrypted_range.clone()], &mut dst[encrypted_range.start..])?;

        //{
        //    debug!("Encrypted size in bytes = {} compared to encrypted range {:?}", encrypted_size, encrypted_range);
        //    Self::log_crypto_data("Decrypted data", src);
        //    Self::log_crypto_data("Encrypted data", &dst[0..encrypted_size]);
        //}

        Ok(encrypted_range.start + encrypted_size)
    }

    /// Verify that the padding is correct. Padding is expected to be before the supplied padding end index.
    ///
    /// Function returns the padding range so caller can strip the range if it so desires.
    fn verify_padding(&self, src: &[u8], key_size: usize, padding_end: usize) -> Result<Range<usize>, StatusCode> {
        let (padding_byte, padding_range) = if key_size > 256 {
            let extra_padding_byte = src[padding_end - 1];
            let padding_byte = src[padding_end - 2];
            let padding_size = ((extra_padding_byte as usize) << 8) + (padding_byte as usize);
            (padding_byte, (padding_end - padding_size - 1)..(padding_end - 1))
        } else {
            let padding_byte = src[padding_end - 1];
            let padding_size = padding_byte as usize;
            (padding_byte, (padding_end - padding_size - 1)..padding_end)
        };
        trace!("Padding byte {} check on range {:?}", padding_byte, padding_range);
        for (i, b) in src[padding_range.clone()].iter().enumerate() {
            if *b != padding_byte {
                error!("Expected padding byte {}, got {} at index {}", padding_byte, *b, i);
                return Err(BAD_SECURITY_CHECKS_FAILED);
            }
        }
        Ok(padding_range)
    }

    fn asymmetric_decrypt_and_verify(&self, security_policy: SecurityPolicy, verification_key: &PKey, receiver_thumbprint: ByteString, src: &[u8], encrypted_range: Range<usize>, their_key: Option<PKey>, dst: &mut [u8]) -> Result<usize, StatusCode> {
        // Asymmetric encrypt requires the caller supply the security policy
        match security_policy {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {}
            _ => {
                return Err(BAD_SECURITY_POLICY_REJECTED);
            }
        }

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
            dst[..encrypted_range.start].copy_from_slice(&src[..encrypted_range.start]);

            // Decrypt and copy encrypted block
            // Note that the unencrypted size can be less than the encrypted size due to removal
            // of padding, so the ranges that were supplied to this function must be offset to compensate.
            let encrypted_size = encrypted_range.end - encrypted_range.start;
            trace!("Decrypting message range {:?}", encrypted_range);
            let mut decrypted_tmp = vec![0u8; encrypted_size];

            let private_key = self.private_key.as_ref().unwrap();
            let decrypted_size = security_policy.asymmetric_decrypt(private_key, &src[encrypted_range.clone()], &mut decrypted_tmp)?;
            trace!("Decrypted bytes = {} compared to encrypted range {}", decrypted_size, encrypted_size);
            Self::log_crypto_data("Decrypted Bytes = ", &decrypted_tmp[..decrypted_size]);

            let verification_key_signature_size = verification_key.size();
            trace!("Verification key size = {}", verification_key_signature_size);

            // Copy the bytes to dst
            dst[encrypted_range.start..(encrypted_range.start + decrypted_size)].copy_from_slice(&decrypted_tmp[0..decrypted_size]);

            // The signature range is at the end of the decrypted block for the verification key's signature
            let signature_dst_offset = encrypted_range.start + decrypted_size - verification_key_signature_size;
            let signature_range_dst = signature_dst_offset..(signature_dst_offset + verification_key_signature_size);

            // The signed range is from 0 to the end of the plaintext except for key size
            let signed_range_dst = 0..signature_dst_offset;

            Self::log_crypto_data("Decrypted data = ", &dst[..signature_range_dst.end]);

            // Verify signature (contained encrypted portion) using verification key
            trace!("Verifying signature range {:?} with signature at {:?}", signed_range_dst, signature_range_dst);
            security_policy.asymmetric_verify_signature(verification_key, &dst[signed_range_dst.clone()], &dst[signature_range_dst.clone()], their_key)?;

            // Verify that the padding is correct
            let _ = self.verify_padding(dst, verification_key.size(), signature_range_dst.start)?;

            // Decrypted and verified into dst
            Ok(signature_range_dst.start)
        }
    }

    fn server_keys(&self) -> &(Vec<u8>, AesKey, Vec<u8>) {
        self.server_keys.as_ref().unwrap()
    }

    fn client_keys(&self) -> &(Vec<u8>, AesKey, Vec<u8>) {
        self.client_keys.as_ref().unwrap()
    }

    fn encryption_keys(&self) -> (&AesKey, &[u8]) {
        let keys = self.server_keys();
        (&keys.1, &keys.2)
    }

    fn signing_key(&self) -> &[u8] {
        &(self.server_keys()).0
    }

    fn decryption_keys(&self) -> (&AesKey, &[u8]) {
        let keys = self.client_keys();
        (&keys.1, &keys.2)
    }

    fn verification_key(&self) -> &[u8] {
        &(self.client_keys()).0
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
    pub fn symmetric_sign_and_encrypt(&self, src: &[u8], signed_range: Range<usize>, encrypted_range: Range<usize>, dst: &mut [u8]) -> Result<usize, StatusCode> {
        let encrypted_size = match self.security_mode {
            MessageSecurityMode::None => {
                trace!("encrypt_and_sign is doing nothing because security mode == None");
                // Just copy data to out
                dst.copy_from_slice(src);

                src.len()
            }
            MessageSecurityMode::Sign => {
                trace!("encrypt_and_sign security mode == Sign");
                self.expect_supported_security_policy();
                self.symmetric_sign(src, signed_range, dst)?
            }
            MessageSecurityMode::SignAndEncrypt => {
                trace!("encrypt_and_sign security mode == SignAndEncrypt, signed_range = {:?}, encrypted_range = {:?}", signed_range, encrypted_range);
                self.expect_supported_security_policy();

                let mut dst_tmp = vec![0u8; dst.len() + 16]; // tmp includes +16 for blocksize

                // Sign the block
                let _ = self.symmetric_sign(src, signed_range, &mut dst_tmp)?;

                // Encrypt the sequence header, payload, signature
                let (key, iv) = self.encryption_keys();
                let encrypted_size = self.security_policy.symmetric_encrypt(key, iv, &dst_tmp[encrypted_range.clone()], &mut dst[encrypted_range.start..(encrypted_range.end + 16)])?;
                // Copy the message header / security header
                dst[..encrypted_range.start].copy_from_slice(&dst_tmp[..encrypted_range.start]);

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
        trace!("signed_range = {:?}, signature range = {:?}, signature len = {}", signed_range, signature_range, signature_size);

        // Sign the message header, security header, sequence header, body, padding
        let signing_key = self.signing_key();
        self.security_policy.symmetric_sign(signing_key, &src[signed_range.clone()], &mut signature)?;

        trace!("Signature, len {} = {:?}", signature.len(), signature);

        // Copy the signed portion and the signature to the destination
        dst[signed_range.clone()].copy_from_slice(&src[signed_range.clone()]);
        dst[signature_range.clone()].copy_from_slice(&signature);

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
                dst[..].copy_from_slice(&src[..]);
                Ok(src.len())
            }
            MessageSecurityMode::Sign => {
                self.expect_supported_security_policy();
                // Copy everything
                let all = ..src.len();
                trace!("copying from slice {:?}", all);
                dst[all].copy_from_slice(&src[all]);
                // Verify signature
                trace!("Verifying range from {:?} to signature {}..", signed_range, signed_range.end);
                let verification_key = self.verification_key();
                self.security_policy.symmetric_verify_signature(verification_key, &dst[signed_range.clone()], &dst[signed_range.end..])?;

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
                dst[..encrypted_range.start].copy_from_slice(&src[..encrypted_range.start]);

                // Decrypt encrypted portion
                let mut decrypted_tmp = vec![0u8; ciphertext_size + 16]; // tmp includes +16 for blocksize
                let (key, iv) = self.decryption_keys();

                trace!("Secure decrypt called with encrypted range {:?}", encrypted_range);
                let decrypted_size = self.security_policy.symmetric_decrypt(key, iv, &src[encrypted_range.clone()], &mut decrypted_tmp[..])?;

                // Self::log_crypto_data("Encrypted buffer", &src[..encrypted_range.end]);
                let encrypted_range = encrypted_range.start..(encrypted_range.start + decrypted_size);
                dst[encrypted_range.clone()].copy_from_slice(&decrypted_tmp[..decrypted_size]);
                Self::log_crypto_data("Decrypted buffer", &dst[..encrypted_range.end]);

                // Verify signature (after encrypted portion)
                let signature_range = (encrypted_range.end - self.security_policy.symmetric_signature_size())..encrypted_range.end;
                trace!("signed range = {:?}, signature range = {:?}", signed_range, signature_range);
                let verification_key = self.verification_key();
                self.security_policy.symmetric_verify_signature(verification_key, &dst[signed_range.clone()], &dst[signature_range])?;
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
