use std;
use std::io::{Read, Write, Cursor};

use opcua_types::*;

use crypto::security_policy::SecurityPolicy;
use crypto::X509;

use comms::{MESSAGE_CHUNK_HEADER_SIZE, CHUNK_MESSAGE, CLOSE_SECURE_CHANNEL_MESSAGE, OPEN_SECURE_CHANNEL_MESSAGE};
use comms::{CHUNK_INTERMEDIATE, CHUNK_FINAL, CHUNK_FINAL_ERROR};
use comms::{SequenceHeader, SecurityHeader, AsymmetricSecurityHeader, SymmetricSecurityHeader};
use comms::SecureChannel;
use comms::ChunkInfo;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageChunkType {
    Message,
    OpenSecureChannel,
    CloseSecureChannel
}

impl MessageChunkType {
    pub fn is_open_secure_channel(&self) -> bool {
        *self == MessageChunkType::OpenSecureChannel
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageIsFinalType {
    /// Intermediate
    Intermediate,
    /// Final chunk
    Final,
    /// Abort
    FinalError,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageChunkHeader {
    /// The kind of chunk - message, open or close
    pub message_type: MessageChunkType,
    /// The chunk type - C == intermediate, F = the final chunk, A = the final chunk when aborting
    pub is_final: MessageIsFinalType,
    /// The size of the chunk (message) including the header
    pub message_size: UInt32,
    /// Secure channel id
    pub secure_channel_id: UInt32,
    /// valid flag
    pub is_valid: bool,
}

impl BinaryEncoder<MessageChunkHeader> for MessageChunkHeader {
    fn byte_len(&self) -> usize {
        MESSAGE_CHUNK_HEADER_SIZE
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        if !self.is_valid {
            error!("Cannot write an invalid type");
            return Ok(0);
        }

        let message_type = match self.message_type {
            MessageChunkType::Message => { CHUNK_MESSAGE }
            MessageChunkType::OpenSecureChannel => {
                OPEN_SECURE_CHANNEL_MESSAGE
            }
            MessageChunkType::CloseSecureChannel => {
                CLOSE_SECURE_CHANNEL_MESSAGE
            }
        };

        let is_final: u8 = match self.is_final {
            MessageIsFinalType::Intermediate => { CHUNK_INTERMEDIATE }
            MessageIsFinalType::Final => { CHUNK_FINAL }
            MessageIsFinalType::FinalError => { CHUNK_FINAL_ERROR }
        };

        let mut size = 0;
        size += process_encode_io_result(stream.write(&message_type))?;
        size += write_u8(stream, is_final)?;
        size += write_u32(stream, self.message_size)?;
        size += write_u32(stream, self.secure_channel_id)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let mut is_valid = true;

        let mut message_type_code = [0u8; 3];
        process_decode_io_result(stream.read_exact(&mut message_type_code))?;
        let message_type = if message_type_code == CHUNK_MESSAGE {
            MessageChunkType::Message
        } else if message_type_code == OPEN_SECURE_CHANNEL_MESSAGE {
            MessageChunkType::OpenSecureChannel
        } else if message_type_code == CLOSE_SECURE_CHANNEL_MESSAGE {
            MessageChunkType::CloseSecureChannel
        } else {
            error!("Invalid message code");
            is_valid = false;
            MessageChunkType::Message
        };

        let chunk_type_code = read_u8(stream)?;
        let is_final = match chunk_type_code {
            CHUNK_FINAL => { MessageIsFinalType::Final }
            CHUNK_INTERMEDIATE => { MessageIsFinalType::Intermediate }
            CHUNK_FINAL_ERROR => { MessageIsFinalType::FinalError }
            _ => {
                error!("Invalid chunk type");
                is_valid = false;
                MessageIsFinalType::FinalError
            }
        };

        let message_size = read_u32(stream)?;
        let secure_channel_id = read_u32(stream)?;

        Ok(MessageChunkHeader {
            message_type: message_type,
            is_final: is_final,
            message_size: message_size,
            secure_channel_id: secure_channel_id,
            is_valid: is_valid,
        })
    }
}

impl MessageChunkHeader {}

/// A chunk holds a part or the whole of a message. The chunk may be signed and encrypted. To
/// extract the message may require one or more chunks.
#[derive(Debug)]
pub struct MessageChunk {
    /// All of the chunk's data including headers, payload, padding, signature
    pub data: Vec<u8>,
}

impl BinaryEncoder<MessageChunk> for MessageChunk {
    fn byte_len(&self) -> usize {
        self.data.len()
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let result = stream.write(&self.data);
        if result.is_err() {
            Err(BAD_ENCODING_ERROR)
        } else {
            Ok(result.unwrap())
        }
    }

    fn decode<S: Read>(in_stream: &mut S) -> EncodingResult<Self> {
        // Read the header out first
        let chunk_header_result = MessageChunkHeader::decode(in_stream);
        if chunk_header_result.is_err() {
            error!("Cannot decode chunk header {:?}", chunk_header_result.unwrap_err());
            return Err(BAD_COMMUNICATION_ERROR);
        }

        let chunk_header = chunk_header_result.unwrap();
        if !chunk_header.is_valid {
            return Err(BAD_TCP_MESSAGE_TYPE_INVALID);
        }

        // Now make a 
        let data = vec![0u8; chunk_header.message_size as usize];
        let mut stream = Cursor::new(data);

        // Write header to a buffer
        let chunk_header_size = chunk_header.encode(&mut stream)?;
        assert_eq!(chunk_header_size, MESSAGE_CHUNK_HEADER_SIZE);

        // Get the data (with header written to it)
        let mut data = stream.into_inner();

        // Read remainder of stream into slice after the header
        let _ = in_stream.read_exact(&mut data[chunk_header_size..]);

        Ok(MessageChunk { data })
    }
}

impl MessageChunk {
    pub fn new(sequence_number: UInt32, request_id: UInt32, message_type: MessageChunkType, is_final: MessageIsFinalType, secure_channel: &SecureChannel, data: &[u8], message_size: usize) -> Result<MessageChunk, StatusCode> {
        // security header depends on message type
        let security_header = secure_channel.make_security_header(message_type);
        let sequence_header = SequenceHeader { sequence_number, request_id };

        // Calculate the chunk body size
        let mut message_chunk_size = MESSAGE_CHUNK_HEADER_SIZE;
        message_chunk_size += security_header.byte_len();
        message_chunk_size += sequence_header.byte_len();
        message_chunk_size += data.len();
        // Test if padding is required
        let padding_size = secure_channel.calc_chunk_padding(data.len(), &security_header, message_size);
        if padding_size > 0 {
            message_chunk_size += padding_size;
            if padding_size > 255 {
                message_chunk_size += 1;
            }
        }
        // Signature size (if required)
        message_chunk_size += secure_channel.symmetric_signature_size();

        let mut stream = Cursor::new(vec![0u8; message_chunk_size]);

        debug!("Creating a chunk with a size of {}", message_chunk_size);
        let secure_channel_id = secure_channel.secure_channel_id;
        let chunk_header = MessageChunkHeader {
            message_type,
            is_final,
            message_size: message_chunk_size as u32,
            secure_channel_id,
            is_valid: true,
        };

        // write chunk header
        let _ = chunk_header.encode(&mut stream);
        // write security header
        let _ = security_header.encode(&mut stream);
        // write sequence header
        let _ = sequence_header.encode(&mut stream);
        // write message
        let _ = stream.write(data);
        // write padding byte?
        if padding_size > 0 {
            // A number of bytes are written out equal to the padding size.
            // Each byte is the padding size. So if padding size is 15 then
            // there will be 15 bytes all with the value 15
            let padding_value = (padding_size & 0xff) as u8;
            for _ in 0..padding_size {
                let _ = write_u8(&mut stream, padding_value)?;
            }
            // For key sizes > 2048, there may be an extra byte if padding exceeds 255 chars
            // NOTE this doesn't make any sense to me - if I add this byte then the padding is off by
            // 1 for the block size. It would make sense when padding_size > 255 for the last padding
            // byte to hold the extra padding size.
            if padding_size > 255 {
                let extra_padding_size = (padding_size >> 8) as u8;
                let _ = write_u8(&mut stream, extra_padding_size)?;
            }
        }
        //... The buffer has zeros for the signature 

        Ok(MessageChunk { data: stream.into_inner() })
    }

    /// Calculates the body size that fit inside of a message chunk of a particular size.
    /// This requires calculating the size of the header, the signature, padding etc. and deducting it
    /// to reveal the message size
    pub fn body_size_from_message_size(message_type: MessageChunkType, secure_channel: &SecureChannel, message_size: usize) -> usize {
        if message_size < 8192 {
            panic!("max chunk size cannot be less than minimum in the spec");
        }

        let security_header = secure_channel.make_security_header(message_type);

        let mut data_size = MESSAGE_CHUNK_HEADER_SIZE;
        data_size += security_header.byte_len();
        data_size += (SequenceHeader { sequence_number: 0, request_id: 0 }).byte_len();

        // 1 byte == most padding
        let padding_size = secure_channel.calc_chunk_padding(1, &security_header, message_size);
        if padding_size > 0 {
            data_size += padding_size;
            if padding_size > 255 {
                // Extra padding byte
                data_size += 1;
            }
        }

        // signature length
        data_size += secure_channel.symmetric_signature_size();

        // Message size is what's left
        message_size - data_size
    }

    pub fn message_header(&self) -> Result<MessageChunkHeader, StatusCode> {
        // Message header is first so just read it
        let mut stream = Cursor::new(&self.data);
        MessageChunkHeader::decode(&mut stream)
    }

    pub fn security_header(&self) -> Result<SecurityHeader, StatusCode> {
        // Message header is first so just read it
        let mut stream = Cursor::new(&self.data);
        let message_header = MessageChunkHeader::decode(&mut stream)?;
        let security_header = if message_header.message_type == MessageChunkType::OpenSecureChannel {
            SecurityHeader::Asymmetric(AsymmetricSecurityHeader::decode(&mut stream)?)
        } else {
            SecurityHeader::Symmetric(SymmetricSecurityHeader::decode(&mut stream)?)
        };
        Ok(security_header)
    }

    /// Signs and encrypts the data
    pub fn apply_security(&mut self, secure_channel: &mut SecureChannel) -> Result<(), StatusCode> {
        if secure_channel.signing_enabled() || secure_channel.encryption_enabled() {
            // S - Message Header
            // S - Security Header
            // S - Sequence Header - E
            // S - Body            - E
            // S - Padding         - E
            //     Signature       - E
            let chunk_info = self.chunk_info(secure_channel)?;
            let encrypted_range = chunk_info.sequence_header_offset..self.data.len();

            // Allow big chunk of space for any padding, signature
            let mut encrypted_data = vec![0u8; self.data.len() + 1024];

            // Encrypt and sign - open secure channel
            let encrypted_size = if self.is_open_secure_channel() {
                secure_channel.asymmetric_encrypt_and_sign(secure_channel.security_policy, &self.data, encrypted_range, &mut encrypted_data)?
            } else {
                // Symmetric encrypt and sign
                let signed_range = 0..(self.data.len() - secure_channel.security_policy.symmetric_signature_size());
                secure_channel.symmetric_encrypt_and_sign(&self.data, signed_range, encrypted_range, &mut encrypted_data)?
            };

            self.data.clear();
            self.data.extend_from_slice(&encrypted_data[0..encrypted_size]);
        }
        Ok(())
    }

    /// Decrypts and verifies the body data if the mode / policy requires it
    pub fn verify_and_remove_security(&mut self, secure_channel: &mut SecureChannel) -> Result<(), StatusCode> {
        // S - Message Header
        // S - Security Header
        // S - Sequence Header - E
        // S - Body            - E
        // S - Padding         - E
        //     Signature       - E
        if self.is_open_secure_channel() {
            // The OpenSecureChannel is the first thing we receive so we must examine
            // the security policy and use it to determine if the packet must be decrypted.
            let (security_header, encrypted_data_offset, message_size) = {
                let mut stream = Cursor::new(&self.data);
                let message_header = MessageChunkHeader::decode(&mut stream)?;
                let security_header = AsymmetricSecurityHeader::decode(&mut stream)?;
                (security_header, stream.position() as usize, message_header.message_size as usize)
            };
            let encrypted_range = encrypted_data_offset..message_size;

            debug!("Decrypting OpenSecureChannel");

            // The security policy dictates the encryption / signature algorithms used by the request
            let security_policy = SecurityPolicy::from_uri(security_header.security_policy_uri.as_ref());
            match security_policy {
                SecurityPolicy::Unknown => {
                    return Err(BAD_SECURITY_POLICY_REJECTED);
                }
                SecurityPolicy::None => {
                    // Nothing to do
                    return Ok(());
                }
                _ => {}
            }

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
            debug!("Sender certificate byte length = {}", sender_certificate_len);
            let sender_certificate = X509::from_byte_string(&security_header.sender_certificate)?;

            let verification_key = sender_certificate.public_key()?;
            let signature_size = verification_key.bit_length() / 8;
            debug!("Sender public key byte length = {}", signature_size);

            let receiver_thumbprint = security_header.receiver_certificate_thumbprint;

            let mut decrypted_data = vec![0u8; message_size];
            let decrypted_size = secure_channel.asymmetric_decrypt_and_verify(security_policy, &verification_key, receiver_thumbprint, &self.data, encrypted_range, &mut decrypted_data)?;

            self.data.clear();
            self.data.extend_from_slice(&decrypted_data[0..decrypted_size]);
        } else if secure_channel.signing_enabled() || secure_channel.encryption_enabled() {
            // Symmetric decrypt and verify
            let (encrypted_data_offset, message_size) = {
                let mut stream = Cursor::new(&self.data);
                let message_header = MessageChunkHeader::decode(&mut stream)?;
                let _ = SymmetricSecurityHeader::decode(&mut stream)?;
                (stream.position() as usize, message_header.message_size as usize)
            };

            let encrypted_range = encrypted_data_offset..message_size;
            let signed_range = 0..(message_size - secure_channel.security_policy.symmetric_signature_size());
            debug!("Decrypting block with signature info {:?} and encrypt info {:?}", signed_range, encrypted_range);

            let mut decrypted_data = vec![0u8; message_size];
            secure_channel.symmetric_decrypt_and_verify(&self.data, signed_range, encrypted_range, &mut decrypted_data)?;

            self.data = decrypted_data;
        }

        Ok(())
    }

    pub fn is_open_secure_channel(&self) -> bool {
        if let Ok(message_header) = self.message_header() {
            message_header.message_type.is_open_secure_channel()
        } else {
            false
        }
    }

    pub fn chunk_info(&self, secure_channel: &SecureChannel) -> std::result::Result<ChunkInfo, StatusCode> {
        ChunkInfo::new(self, secure_channel)
    }
}
