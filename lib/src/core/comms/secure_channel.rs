// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{
    io::{Cursor, Write},
    ops::Range,
    sync::Arc,
};

use chrono::Duration;

use crate::crypto::{
    aeskey::AesKey,
    pkey::{KeySize, PrivateKey, PublicKey},
    random,
    x509::X509,
    CertificateStore, SecurityPolicy,
};
use crate::sync::*;
use crate::types::{
    service_types::ChannelSecurityToken, status_code::StatusCode, write_bytes, write_u8,
    BinaryEncoder, ByteString, DateTime, DecodingOptions, MessageSecurityMode,
};

use super::{
    message_chunk::{MessageChunk, MessageChunkHeader, MessageChunkType},
    security_header::{AsymmetricSecurityHeader, SecurityHeader, SymmetricSecurityHeader},
};

#[derive(Debug, PartialEq)]
pub enum Role {
    Unknown,
    Client,
    Server,
}

/// Holds all of the security information related to this session
#[derive(Debug)]
pub struct SecureChannel {
    // The side of the secure channel that this role belongs to, client or server
    role: Role,
    /// The security policy for the connection, None or Encryption/Signing settings
    security_policy: SecurityPolicy,
    /// The security mode for the connection, None, Sign, SignAndEncrypt
    security_mode: MessageSecurityMode,
    /// Secure channel id
    secure_channel_id: u32,
    /// Token creation time.
    token_created_at: DateTime,
    /// Token lifetime
    token_lifetime: u32,
    /// Token identifier
    token_id: u32,
    /// Our certificate
    cert: Option<X509>,
    /// Our private key
    private_key: Option<PrivateKey>,
    /// Their certificate
    remote_cert: Option<X509>,
    /// Their nonce provided by open secure channel
    remote_nonce: Vec<u8>,
    /// Our nonce generated while handling open secure channel
    local_nonce: Vec<u8>,
    /// Client (i.e. other end's set of keys) Symmetric Signing Key, Encrypt Key, IV
    remote_keys: Option<(Vec<u8>, AesKey, Vec<u8>)>,
    /// Server (i.e. our end's set of keys) Symmetric Signing Key, Decrypt Key, IV
    local_keys: Option<(Vec<u8>, AesKey, Vec<u8>)>,
    /// Decoding options
    decoding_options: DecodingOptions,
}

impl SecureChannel {
    /// For testing purposes only
    #[cfg(test)]
    pub fn new_no_certificate_store() -> SecureChannel {
        SecureChannel {
            role: Role::Unknown,
            security_policy: SecurityPolicy::None,
            security_mode: MessageSecurityMode::None,
            secure_channel_id: 0,
            token_id: 0,
            token_created_at: DateTime::now(),
            token_lifetime: 0,
            local_nonce: Vec::new(),
            remote_nonce: Vec::new(),
            cert: None,
            private_key: None,
            remote_cert: None,
            local_keys: None,
            remote_keys: None,
            decoding_options: DecodingOptions::default(),
        }
    }

    pub fn new(
        certificate_store: Arc<RwLock<CertificateStore>>,
        role: Role,
        decoding_options: DecodingOptions,
    ) -> SecureChannel {
        let (cert, private_key) = {
            let certificate_store = certificate_store.read();
            if let Ok((cert, pkey)) = certificate_store.read_own_cert_and_pkey() {
                (Some(cert), Some(pkey))
            } else {
                error!("Cannot read our own certificate and private key. Check paths. Crypto won't work");
                (None, None)
            }
        };
        SecureChannel {
            role,
            security_mode: MessageSecurityMode::None,
            security_policy: SecurityPolicy::None,
            secure_channel_id: 0,
            token_id: 0,
            token_created_at: DateTime::now(),
            token_lifetime: 0,
            local_nonce: Vec::new(),
            remote_nonce: Vec::new(),
            cert,
            private_key,
            remote_cert: None,
            local_keys: None,
            remote_keys: None,
            decoding_options,
        }
    }

    pub fn is_client_role(&self) -> bool {
        self.role == Role::Client
    }

    pub fn set_cert(&mut self, cert: Option<X509>) {
        self.cert = cert;
    }

    pub fn cert(&self) -> Option<X509> {
        self.cert.clone()
    }

    pub fn set_remote_cert(&mut self, remote_cert: Option<X509>) {
        self.remote_cert = remote_cert;
    }

    pub fn remote_cert(&self) -> Option<X509> {
        self.remote_cert.clone()
    }

    pub fn set_private_key(&mut self, private_key: Option<PrivateKey>) {
        self.private_key = private_key;
    }

    pub fn security_mode(&self) -> MessageSecurityMode {
        self.security_mode
    }

    pub fn set_security_mode(&mut self, security_mode: MessageSecurityMode) {
        self.security_mode = security_mode;
    }

    pub fn security_policy(&self) -> SecurityPolicy {
        self.security_policy
    }

    pub fn set_security_policy(&mut self, security_policy: SecurityPolicy) {
        self.security_policy = security_policy;
    }

    pub fn clear_security_token(&mut self) {
        self.secure_channel_id = 0;
        self.token_id = 0;
        self.token_created_at = DateTime::now();
        self.token_lifetime = 0;
    }

    pub fn set_security_token(&mut self, channel_token: ChannelSecurityToken) {
        self.secure_channel_id = channel_token.channel_id;
        self.token_id = channel_token.token_id;
        self.token_created_at = DateTime::now();
        self.token_lifetime = channel_token.revised_lifetime;
    }

    pub fn set_secure_channel_id(&mut self, secure_channel_id: u32) {
        self.secure_channel_id = secure_channel_id;
    }

    pub fn secure_channel_id(&self) -> u32 {
        self.secure_channel_id
    }

    pub fn token_created_at(&self) -> DateTime {
        self.token_created_at
    }

    pub fn token_lifetime(&self) -> u32 {
        self.token_lifetime
    }

    pub fn set_token_id(&mut self, token_id: u32) {
        self.token_id = token_id;
    }

    pub fn token_id(&self) -> u32 {
        self.token_id
    }

    pub fn set_client_offset(&mut self, client_offset: Duration) {
        self.decoding_options.client_offset = client_offset;
    }

    pub fn set_decoding_options(&mut self, decoding_options: DecodingOptions) {
        self.decoding_options = DecodingOptions {
            client_offset: self.decoding_options.client_offset,
            ..decoding_options
        }
    }

    pub fn decoding_options(&self) -> DecodingOptions {
        self.decoding_options.clone()
    }

    /// Test if the secure channel token needs to be renewed. The algorithm determines it needs
    /// to be renewed if the issue period has elapsed by 75% or more.
    pub fn should_renew_security_token(&self) -> bool {
        if self.token_id() == 0 {
            false
        } else {
            // Check if secure channel 75% close to expiration in which case send a renew
            let renew_lifetime = (self.token_lifetime() * 3) / 4;
            let renew_lifetime = Duration::milliseconds(renew_lifetime as i64);
            // Renew the token?
            DateTime::now() - self.token_created_at() > renew_lifetime
        }
    }

    /// Makes a security header according to the type of message being sent, symmetric or asymmetric
    pub fn make_security_header(&self, message_type: MessageChunkType) -> SecurityHeader {
        match message_type {
            MessageChunkType::OpenSecureChannel => {
                let asymmetric_security_header = if self.security_policy == SecurityPolicy::None {
                    trace!("AsymmetricSecurityHeader security policy none");
                    AsymmetricSecurityHeader::none()
                } else {
                    let receiver_certificate_thumbprint =
                        if let Some(ref remote_cert) = self.remote_cert {
                            remote_cert.thumbprint().as_byte_string()
                        } else {
                            ByteString::null()
                        };
                    AsymmetricSecurityHeader::new(
                        self.security_policy,
                        self.cert.as_ref().unwrap(),
                        receiver_certificate_thumbprint,
                    )
                };
                debug!(
                    "AsymmetricSecurityHeader = {:?}",
                    asymmetric_security_header
                );
                SecurityHeader::Asymmetric(asymmetric_security_header)
            }
            _ => SecurityHeader::Symmetric(SymmetricSecurityHeader {
                token_id: self.token_id,
            }),
        }
    }

    /// Creates a nonce for the connection. The nonce should be the same size as the symmetric key
    pub fn create_random_nonce(&mut self) {
        self.local_nonce
            .resize(self.security_policy.secure_channel_nonce_length(), 0);
        random::bytes(&mut self.local_nonce);
    }

    /// Sets the remote certificate
    pub fn set_remote_cert_from_byte_string(
        &mut self,
        remote_cert: &ByteString,
    ) -> Result<(), StatusCode> {
        self.remote_cert = if remote_cert.is_null() {
            None
        } else {
            Some(X509::from_byte_string(remote_cert)?)
        };
        Ok(())
    }

    /// Obtains the remote certificate as a byte string
    pub fn remote_cert_as_byte_string(&self) -> ByteString {
        if let Some(ref remote_cert) = self.remote_cert {
            remote_cert.as_byte_string()
        } else {
            ByteString::null()
        }
    }

    /// Set their nonce which should be the same as the symmetric key
    pub fn set_remote_nonce_from_byte_string(
        &mut self,
        remote_nonce: &ByteString,
    ) -> Result<(), StatusCode> {
        if let Some(ref remote_nonce) = remote_nonce.value {
            if self.security_policy != SecurityPolicy::None
                && remote_nonce.len() != self.security_policy.secure_channel_nonce_length()
            {
                error!(
                    "Remote nonce is invalid length {}, expecting {}. {:?}",
                    remote_nonce.len(),
                    self.security_policy.secure_channel_nonce_length(),
                    remote_nonce
                );
                Err(StatusCode::BadNonceInvalid)
            } else {
                self.remote_nonce = remote_nonce.to_vec();
                Ok(())
            }
        } else if self.security_policy != SecurityPolicy::None {
            error!("Remote nonce is invalid {:?}", remote_nonce);
            Err(StatusCode::BadNonceInvalid)
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
        self.remote_keys = Some(
            self.security_policy
                .make_secure_channel_keys(&self.local_nonce, &self.remote_nonce),
        );
        self.local_keys = Some(
            self.security_policy
                .make_secure_channel_keys(&self.remote_nonce, &self.local_nonce),
        );
        trace!("Remote nonce = {:?}", self.remote_nonce);
        trace!("Local nonce = {:?}", self.local_nonce);
        trace!("Derived remote keys = {:?}", self.remote_keys);
        trace!("Derived local keys = {:?}", self.local_keys);
    }

    /// Test if the token has expired yet
    pub fn token_has_expired(&self) -> bool {
        let token_created_at = self.token_created_at;
        let token_expires = token_created_at + Duration::seconds(self.token_lifetime as i64);
        DateTime::now().ge(&token_expires)
    }

    /// Calculates the signature size for a message depending on the supplied security header
    pub fn signature_size(&self, security_header: &SecurityHeader) -> usize {
        // Signature size in bytes
        match security_header {
            SecurityHeader::Asymmetric(security_header) => {
                if !security_header.sender_certificate.is_null() {
                    let x509 = X509::from_byte_string(&security_header.sender_certificate).unwrap();
                    x509.public_key().unwrap().size()
                } else {
                    trace!("No certificate / public key was supplied in the asymmetric security header");
                    0
                }
            }
            SecurityHeader::Symmetric(_) => {
                // Signature size comes from policy
                self.security_policy.symmetric_signature_size()
            }
        }
    }

    // Extra padding required for keysize > 2048 bits (256 bytes)
    fn minimum_padding(key_length: usize) -> usize {
        if key_length <= 256 {
            1
        } else {
            2
        }
    }

    /// Calculate the padding size
    ///
    /// Padding adds bytes to the body to make it a multiple of the block size so it can be encrypted.
    pub fn padding_size(
        &self,
        security_header: &SecurityHeader,
        body_size: usize,
        signature_size: usize,
    ) -> (usize, usize) {
        if self.security_policy != SecurityPolicy::None
            && self.security_mode != MessageSecurityMode::None
        {
            // Signature size in bytes
            let (plain_text_block_size, key_length) = match security_header {
                SecurityHeader::Asymmetric(security_header) => {
                    if security_header.sender_certificate.is_null() {
                        error!("Sender has not supplied a certificate so it is doubtful that this will work");
                        (self.security_policy.plain_block_size(), signature_size)
                    } else {
                        // Padding requires we look at the remote certificate and security policy
                        let padding = self.security_policy.asymmetric_encryption_padding();
                        let x509 = self.remote_cert().unwrap();
                        let pk = x509.public_key().unwrap();
                        (pk.plain_text_block_size(padding), pk.size())
                    }
                }
                SecurityHeader::Symmetric(_) => {
                    // Plain text block size comes from policy
                    (self.security_policy.plain_block_size(), signature_size)
                }
            };

            // PaddingSize = PlainTextBlockSize – ((BytesToWrite + SignatureSize + 1) % PlainTextBlockSize);
            let minimum_padding = Self::minimum_padding(key_length);
            let encrypt_size = 8 + body_size + signature_size + minimum_padding;
            let padding_size = if encrypt_size % plain_text_block_size != 0 {
                plain_text_block_size - (encrypt_size % plain_text_block_size)
            } else {
                0
            };
            trace!("sequence_header(8) + body({}) + signature ({}) = plain text size = {} / with padding {} = {}, plain_text_block_size = {}", body_size, signature_size, encrypt_size, padding_size, encrypt_size + padding_size, plain_text_block_size);
            (minimum_padding + padding_size, minimum_padding)
        } else {
            (0, 0)
        }
    }

    // Takes an unpadded message chunk and adds padding as well as space to the end to accomodate a signature.
    // Also modifies the message size to include the new padding/signature
    fn add_space_for_padding_and_signature(
        &self,
        message_chunk: &MessageChunk,
    ) -> Result<Vec<u8>, StatusCode> {
        let chunk_info = message_chunk.chunk_info(self)?;
        let data = &message_chunk.data[..];

        let security_header = chunk_info.security_header;

        let buffer = Vec::with_capacity(message_chunk.data.len() + 4096);
        let mut stream = Cursor::new(buffer);

        // First off just write out the src to the buffer. The message header, security header, sequence header and payload
        let _ = stream.write(data);

        // Signature size (if required)
        let signature_size = self.signature_size(&security_header);

        // Write padding
        let body_size = chunk_info.body_length;

        let (padding_size, minimum_padding) =
            self.padding_size(&security_header, body_size, signature_size);
        if padding_size > 0 {
            // A number of bytes are written out equal to the padding size.
            // Each byte is the padding size. So if padding size is 15 then
            // there will be 15 bytes all with the value 15
            if minimum_padding == 1 {
                let padding_byte = ((padding_size - 1) & 0xff) as u8;
                let _ = write_bytes(&mut stream, padding_byte, padding_size)?;
            } else if minimum_padding == 2 {
                // Padding and then extra padding
                let padding_byte = ((padding_size - 2) & 0xff) as u8;
                let extra_padding_byte = ((padding_size - 2) >> 8) as u8;
                trace!(
                    "adding extra padding - padding_byte = {}, extra_padding_byte = {}",
                    padding_byte,
                    extra_padding_byte
                );
                let _ = write_bytes(&mut stream, padding_byte, padding_size - 1)?;
                write_u8(&mut stream, extra_padding_byte)?;
            }
        }

        // Write zeros for the signature
        let _ = write_bytes(&mut stream, 0u8, signature_size)?;

        // Update message header to reflect size with padding + signature
        let message_size = data.len() + padding_size + signature_size;
        Self::update_message_size_and_truncate(
            stream.into_inner(),
            message_size,
            &self.decoding_options,
        )
    }

    fn update_message_size(
        data: &mut [u8],
        message_size: usize,
        decoding_options: &DecodingOptions,
    ) -> Result<(), StatusCode> {
        // Read and rewrite the message_size in the header
        let mut stream = Cursor::new(data);
        let mut message_header = MessageChunkHeader::decode(&mut stream, decoding_options)?;
        stream.set_position(0);
        let old_message_size = message_header.message_size;
        message_header.message_size = message_size as u32;
        message_header.encode(&mut stream)?;
        trace!(
            "Message header message size being modified from {} to {}",
            old_message_size,
            message_size
        );
        Ok(())
    }

    // Truncates a vec and writes the message size
    pub fn update_message_size_and_truncate(
        mut data: Vec<u8>,
        message_size: usize,
        decoding_options: &DecodingOptions,
    ) -> Result<Vec<u8>, StatusCode> {
        Self::update_message_size(&mut data[..], message_size, decoding_options)?;
        // Truncate vector to the size
        data.truncate(message_size);
        Ok(data)
    }

    fn log_crypto_data(message: &str, data: &[u8]) {
        use crate::core::debug;
        debug::log_buffer(message, data);
    }

    /// Applies security to a message chunk and yields a encrypted/signed block to be streamed
    pub fn apply_security(
        &self,
        message_chunk: &MessageChunk,
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        let size = if self.security_policy != SecurityPolicy::None
            && (self.security_mode == MessageSecurityMode::Sign
                || self.security_mode == MessageSecurityMode::SignAndEncrypt)
        {
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
            let encrypted_size = if message_chunk.is_open_secure_channel(&self.decoding_options) {
                self.asymmetric_sign_and_encrypt(self.security_policy, &data, encrypted_range, dst)?
            } else {
                // Symmetric encrypt and sign
                let signed_range =
                    0..(data.len() - self.security_policy.symmetric_signature_size());
                self.symmetric_sign_and_encrypt(&data, signed_range, encrypted_range, dst)?
            };

            Self::log_crypto_data("Chunk after encryption", &dst[..encrypted_size]);

            encrypted_size
        } else {
            let size = message_chunk.data.len();
            if size > dst.len() {
                panic!("The size of the message chunk {} exceeds the size of the destination buffer {}", size, dst.len())
            }
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
    pub fn verify_and_remove_security_forensic(
        &mut self,
        src: &[u8],
        their_key: Option<PrivateKey>,
    ) -> Result<MessageChunk, StatusCode> {
        // Get message & security header from data
        let (message_header, security_header, encrypted_data_offset) = {
            let mut stream = Cursor::new(&src);
            let message_header = MessageChunkHeader::decode(&mut stream, &self.decoding_options)?;
            let security_header = if message_header.message_type.is_open_secure_channel() {
                SecurityHeader::Asymmetric(AsymmetricSecurityHeader::decode(
                    &mut stream,
                    &self.decoding_options,
                )?)
            } else {
                SecurityHeader::Symmetric(SymmetricSecurityHeader::decode(
                    &mut stream,
                    &self.decoding_options,
                )?)
            };
            let encrypted_data_offset = stream.position() as usize;
            (message_header, security_header, encrypted_data_offset)
        };

        let message_size = message_header.message_size as usize;
        if message_size != src.len() {
            error!(
                "The message size {} is not the same as the supplied buffer {}",
                message_size,
                src.len()
            );
            return Err(StatusCode::BadUnexpectedError);
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
            let security_policy_uri = security_header.security_policy_uri.as_ref();
            let security_policy = SecurityPolicy::from_uri(security_policy_uri);
            match security_policy {
                SecurityPolicy::Unknown => {
                    error!("Security policy \"{}\" provided by client is unknown so it is has been rejected", security_policy_uri);
                    return Err(StatusCode::BadSecurityPolicyRejected);
                }
                SecurityPolicy::None => {
                    // Nothing to do
                    return Ok(MessageChunk { data: src.to_vec() });
                }
                _ => {}
            }
            self.security_policy = security_policy;

            // Asymmetric decrypt and verify

            // The OpenSecureChannel Messages are always signed and encrypted if the SecurityMode
            // is not None. Even if the SecurityMode is Sign and not SignAndEncrypt.

            // An OpenSecureChannelRequest uses Asymmetric encryption - decrypt using the server's private
            // key, verify signature with client's public key.

            // This code doesn't *care* if the cert is trusted, merely that it was used to sign the message
            if security_header.sender_certificate.is_null() {
                error!("Sender certificate is NULL!!!");
                // TODO return
            }

            let sender_certificate_len = security_header
                .sender_certificate
                .value
                .as_ref()
                .unwrap()
                .len();
            trace!(
                "Sender certificate byte length = {}",
                sender_certificate_len
            );
            let sender_certificate = X509::from_byte_string(&security_header.sender_certificate)?;

            let verification_key = sender_certificate.public_key()?;
            let receiver_thumbprint = security_header.receiver_certificate_thumbprint;
            trace!("Receiver thumbprint = {:?}", receiver_thumbprint);

            let mut decrypted_data = vec![0u8; message_size];
            let decrypted_size = self.asymmetric_decrypt_and_verify(
                security_policy,
                &verification_key,
                receiver_thumbprint,
                src,
                encrypted_range,
                their_key,
                &mut decrypted_data,
            )?;

            Self::update_message_size_and_truncate(
                decrypted_data,
                decrypted_size,
                &self.decoding_options,
            )?
        } else if self.security_policy != SecurityPolicy::None
            && (self.security_mode == MessageSecurityMode::Sign
                || self.security_mode == MessageSecurityMode::SignAndEncrypt)
        {
            // Symmetric decrypt and verify
            let signature_size = self.security_policy.symmetric_signature_size();
            let encrypted_range = encrypted_data_offset..message_size;
            let signed_range = 0..(message_size - signature_size);
            trace!(
                "Decrypting block with signature info {:?} and encrypt info {:?}",
                signed_range,
                encrypted_range
            );

            let mut decrypted_data = vec![0u8; message_size];
            let decrypted_size = self.symmetric_decrypt_and_verify(
                src,
                signed_range,
                encrypted_range,
                &mut decrypted_data,
            )?;

            // Now we need to strip off signature
            Self::update_message_size_and_truncate(
                decrypted_data,
                decrypted_size - signature_size,
                &self.decoding_options,
            )?
        } else {
            src.to_vec()
        };

        Ok(MessageChunk { data })
    }

    /// Use the security policy to asymmetric encrypt and sign the specified chunk of data
    fn asymmetric_sign_and_encrypt(
        &self,
        security_policy: SecurityPolicy,
        src: &[u8],
        encrypted_range: Range<usize>,
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        let header_size = encrypted_range.start;

        let signing_key = self.private_key.as_ref().unwrap();
        let signing_key_size = signing_key.size();

        let signed_range = 0..(encrypted_range.end - signing_key_size);
        let signature_range = signed_range.end..encrypted_range.end;

        trace!("Header size = {}, Encrypted range = {:?}, Signed range = {:?}, Signature range = {:?}, signature size = {}", header_size, encrypted_range, signed_range, signature_range, signing_key_size);

        let mut signature = vec![0u8; signing_key_size];
        let encryption_key = self.remote_cert.as_ref().unwrap().public_key()?;

        let mut tmp = vec![0u8; encrypted_range.end];
        tmp[signed_range.clone()].copy_from_slice(&src[signed_range.clone()]);

        // Encryption will change the size of the chunk. Since we sign before encrypting, we need to
        // compute that size and change the message header to be that new size
        let cipher_text_size = {
            let padding = security_policy.asymmetric_encryption_padding();
            let plain_text_size = encrypted_range.end - encrypted_range.start;
            let cipher_text_size =
                encryption_key.calculate_cipher_text_size(plain_text_size, padding);
            trace!(
                "plain_text_size = {}, encrypted_text_size = {}",
                plain_text_size,
                cipher_text_size
            );
            cipher_text_size
        };
        Self::update_message_size(
            &mut tmp[..],
            header_size + cipher_text_size,
            &self.decoding_options,
        )?;

        // Sign the message header, security header, sequence header, body, padding
        security_policy.asymmetric_sign(signing_key, &tmp[signed_range], &mut signature)?;
        tmp[signature_range.clone()].copy_from_slice(&signature);
        assert_eq!(encrypted_range.end, signature_range.end);

        Self::log_crypto_data("Chunk after signing", &tmp[..signature_range.end]);

        // Copy the unencrypted message header / security header portion to dst
        dst[..encrypted_range.start].copy_from_slice(&tmp[..encrypted_range.start]);

        // Encrypt the sequence header, payload, signature portion into dst
        let encrypted_size = security_policy.asymmetric_encrypt(
            &encryption_key,
            &tmp[encrypted_range.clone()],
            &mut dst[encrypted_range.start..],
        )?;

        // Validate encrypted size is right
        if encrypted_size != cipher_text_size {
            panic!(
                "Encrypted block size {} is not the same as calculated cipher text size {}",
                encrypted_size, cipher_text_size
            );
        }

        //{
        //    debug!("Encrypted size in bytes = {} compared to encrypted range {:?}", encrypted_size, encrypted_range);
        //    Self::log_crypto_data("Decrypted data", src);
        //    Self::log_crypto_data("Encrypted data", &dst[0..encrypted_size]);
        //}

        Ok(header_size + encrypted_size)
    }

    fn check_padding_bytes(
        padding_bytes: &[u8],
        expected_padding_byte: u8,
        padding_range_start: usize,
    ) -> Result<(), StatusCode> {
        for (i, b) in padding_bytes.iter().enumerate() {
            if *b != expected_padding_byte {
                error!(
                    "Expected padding byte {}, got {} at index {}",
                    expected_padding_byte,
                    *b,
                    padding_range_start + i
                );
                return Err(StatusCode::BadSecurityChecksFailed);
            }
        }
        Ok(())
    }

    /// Verify that the padding is correct. Padding is expected to be before the supplied padding end index.
    ///
    /// Function returns the padding range so caller can strip the range if it so desires.
    fn verify_padding(
        &self,
        src: &[u8],
        key_size: usize,
        padding_end: usize,
    ) -> Result<Range<usize>, StatusCode> {
        let padding_range = if key_size > 256 {
            let padding_byte = src[padding_end - 2];
            let extra_padding_byte = src[padding_end - 1];
            let padding_size = ((extra_padding_byte as usize) << 8) + (padding_byte as usize);
            let padding_range = (padding_end - padding_size - 2)..padding_end;

            trace!("Extra padding - extra_padding_byte = {}, padding_byte = {}, padding_end = {}, padding_size = {}", extra_padding_byte, padding_byte, padding_end, padding_size);

            // Check padding bytes and extra padding byte
            Self::check_padding_bytes(
                &src[padding_range.start..(padding_range.end - 1)],
                padding_byte,
                padding_range.start,
            )?;
            if src[padding_range.end - 1] != extra_padding_byte {
                error!(
                    "Expected extra padding byte {}, at index {}",
                    extra_padding_byte, padding_range.start
                );
                return Err(StatusCode::BadSecurityChecksFailed);
            }
            padding_range
        } else {
            let padding_byte = src[padding_end - 1];
            let padding_size = padding_byte as usize;
            let padding_range = (padding_end - padding_size - 1)..padding_end;
            // Check padding bytes
            Self::check_padding_bytes(
                &src[padding_range.clone()],
                padding_byte,
                padding_range.start,
            )?;
            padding_range
        };
        trace!("padding_range = {:?}", padding_range);
        Ok(padding_range)
    }

    fn asymmetric_decrypt_and_verify(
        &self,
        security_policy: SecurityPolicy,
        verification_key: &PublicKey,
        receiver_thumbprint: ByteString,
        src: &[u8],
        encrypted_range: Range<usize>,
        their_key: Option<PrivateKey>,
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        // Asymmetric encrypt requires the caller supply the security policy
        if !security_policy.is_supported() {
            error!("Security policy {} is not supported by asymmetric_decrypt_and_verify and has been rejected", security_policy);
            return Err(StatusCode::BadSecurityPolicyRejected);
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
        if our_thumbprint.value() != receiver_thumbprint.as_ref() {
            error!("Supplied thumbprint does not match application certificate's thumbprint");
            Err(StatusCode::BadNoValidCertificates)
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
            let decrypted_size = security_policy.asymmetric_decrypt(
                private_key,
                &src[encrypted_range.clone()],
                &mut decrypted_tmp,
            )?;
            trace!(
                "Decrypted bytes = {} compared to encrypted range {}",
                decrypted_size,
                encrypted_size
            );
            // Self::log_crypto_data("Decrypted Bytes = ", &decrypted_tmp[..decrypted_size]);

            let verification_key_signature_size = verification_key.size();
            trace!(
                "Verification key size = {}",
                verification_key_signature_size
            );

            // Copy the bytes to dst
            dst[encrypted_range.start..(encrypted_range.start + decrypted_size)]
                .copy_from_slice(&decrypted_tmp[0..decrypted_size]);

            // The signature range is at the end of the decrypted block for the verification key's signature
            let signature_dst_offset =
                encrypted_range.start + decrypted_size - verification_key_signature_size;
            let signature_range_dst =
                signature_dst_offset..(signature_dst_offset + verification_key_signature_size);

            // The signed range is from 0 to the end of the plaintext except for key size
            let signed_range_dst = 0..signature_dst_offset;

            // Self::log_crypto_data("Decrypted data = ", &dst[..signature_range_dst.end]);

            // Verify signature (contained encrypted portion) using verification key
            trace!(
                "Verifying signature range {:?} with signature at {:?}",
                signed_range_dst,
                signature_range_dst
            );
            // Keysize for padding is publickey length if avaiable
            let key_size = if let Some(rem) = &self.cert {
                if let Ok(cert) = rem.public_key() {
                    cert.size()
                } else {
                    verification_key.size()
                }
            } else {
                verification_key.size()
            };
            security_policy.asymmetric_verify_signature(
                verification_key,
                &dst[signed_range_dst],
                &dst[signature_range_dst.clone()],
                their_key,
            )?;

            // Verify that the padding is correct
            let padding_range = self.verify_padding(dst, key_size, signature_range_dst.start)?;

            // Decrypted and verified into dst
            Ok(padding_range.start)
        }
    }

    pub fn local_nonce(&self) -> &[u8] {
        &self.local_nonce
    }

    pub fn set_local_nonce(&mut self, local_nonce: &[u8]) {
        self.local_nonce.clear();
        self.local_nonce.extend_from_slice(local_nonce);
    }

    pub fn local_nonce_as_byte_string(&self) -> ByteString {
        if self.local_nonce.is_empty() {
            ByteString::null()
        } else {
            ByteString::from(&self.local_nonce)
        }
    }

    pub fn set_remote_nonce(&mut self, remote_nonce: &[u8]) {
        self.remote_nonce.clear();
        self.remote_nonce.extend_from_slice(remote_nonce);
    }

    pub fn remote_nonce(&self) -> &[u8] {
        &self.remote_nonce
    }

    pub fn remote_nonce_as_byte_string(&self) -> ByteString {
        if self.remote_nonce.is_empty() {
            ByteString::null()
        } else {
            ByteString::from(&self.remote_nonce)
        }
    }

    fn local_keys(&self) -> &(Vec<u8>, AesKey, Vec<u8>) {
        self.local_keys.as_ref().unwrap()
    }

    fn remote_keys(&self) -> &(Vec<u8>, AesKey, Vec<u8>) {
        self.remote_keys.as_ref().unwrap()
    }

    fn encryption_keys(&self) -> (&AesKey, &[u8]) {
        let keys = self.local_keys();
        (&keys.1, &keys.2)
    }

    fn signing_key(&self) -> &[u8] {
        &(self.local_keys()).0
    }

    fn decryption_keys(&self) -> (&AesKey, &[u8]) {
        let keys = self.remote_keys();
        (&keys.1, &keys.2)
    }

    fn verification_key(&self) -> &[u8] {
        &(self.remote_keys()).0
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
    pub fn symmetric_sign_and_encrypt(
        &self,
        src: &[u8],
        signed_range: Range<usize>,
        encrypted_range: Range<usize>,
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
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
                let encrypted_size = self.security_policy.symmetric_encrypt(
                    key,
                    iv,
                    &dst_tmp[encrypted_range.clone()],
                    &mut dst[encrypted_range.start..(encrypted_range.end + 16)],
                )?;
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

    fn symmetric_sign(
        &self,
        src: &[u8],
        signed_range: Range<usize>,
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        let signature_size = self.security_policy.symmetric_signature_size();
        let mut signature = vec![0u8; signature_size];
        let signature_range = signed_range.end..(signed_range.end + signature_size);
        trace!(
            "signed_range = {:?}, signature range = {:?}, signature len = {}",
            signed_range,
            signature_range,
            signature_size
        );

        // Sign the message header, security header, sequence header, body, padding
        let signing_key = self.signing_key();
        self.security_policy.symmetric_sign(
            signing_key,
            &src[signed_range.clone()],
            &mut signature,
        )?;

        trace!("Signature, len {} = {:?}", signature.len(), signature);

        // Copy the signed portion and the signature to the destination
        dst[signed_range.clone()].copy_from_slice(&src[signed_range]);
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
    pub fn symmetric_decrypt_and_verify(
        &self,
        src: &[u8],
        signed_range: Range<usize>,
        encrypted_range: Range<usize>,
        dst: &mut [u8],
    ) -> Result<usize, StatusCode> {
        match self.security_mode {
            MessageSecurityMode::None => {
                // Just copy everything from src to dst
                dst[..].copy_from_slice(src);
                Ok(src.len())
            }
            MessageSecurityMode::Sign => {
                self.expect_supported_security_policy();
                // Copy everything
                let all = ..src.len();
                trace!("copying from slice {:?}", all);
                dst[all].copy_from_slice(&src[all]);
                // Verify signature
                trace!(
                    "Verifying range from {:?} to signature {}..",
                    signed_range,
                    signed_range.end
                );
                let verification_key = self.verification_key();
                self.security_policy.symmetric_verify_signature(
                    verification_key,
                    &dst[signed_range.clone()],
                    &dst[signed_range.end..],
                )?;

                Ok(encrypted_range.end)
            }
            MessageSecurityMode::SignAndEncrypt => {
                self.expect_supported_security_policy();

                // There is an expectation that the block is padded so, this is a quick test
                let ciphertext_size = encrypted_range.end - encrypted_range.start;
                //                if ciphertext_size % 16 != 0 {
                //                    error!("The cipher text size is not padded properly, size = {}", ciphertext_size);
                //                    return Err(StatusCode::BadUnexpectedError);
                //                }

                // Copy security header
                dst[..encrypted_range.start].copy_from_slice(&src[..encrypted_range.start]);

                // Decrypt encrypted portion
                let mut decrypted_tmp = vec![0u8; ciphertext_size + 16]; // tmp includes +16 for blocksize
                let (key, iv) = self.decryption_keys();

                trace!(
                    "Secure decrypt called with encrypted range {:?}",
                    encrypted_range
                );
                let decrypted_size = self.security_policy.symmetric_decrypt(
                    key,
                    iv,
                    &src[encrypted_range.clone()],
                    &mut decrypted_tmp[..],
                )?;

                // Self::log_crypto_data("Encrypted buffer", &src[..encrypted_range.end]);
                let encrypted_range =
                    encrypted_range.start..(encrypted_range.start + decrypted_size);
                dst[encrypted_range.clone()].copy_from_slice(&decrypted_tmp[..decrypted_size]);
                Self::log_crypto_data("Decrypted buffer", &dst[..encrypted_range.end]);

                // Verify signature (after encrypted portion)
                let signature_range = (encrypted_range.end
                    - self.security_policy.symmetric_signature_size())
                    ..encrypted_range.end;
                trace!(
                    "signed range = {:?}, signature range = {:?}",
                    signed_range,
                    signature_range
                );
                let verification_key = self.verification_key();
                self.security_policy.symmetric_verify_signature(
                    verification_key,
                    &dst[signed_range],
                    &dst[signature_range],
                )?;
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
            SecurityPolicy::Basic128Rsa15
            | SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => {}
            _ => {
                panic!("Unsupported security policy");
            }
        }
    }
}
