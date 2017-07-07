use std;
use std::io::{Read, Write, Cursor};

use opcua_types::*;

use comms::*;
use crypto::SecurityPolicy;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChunkMessageType {
    Message,
    OpenSecureChannel,
    CloseSecureChannel
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChunkType {
    /// Intermediate
    Intermediate,
    /// Final chunk
    Final,
    /// Abort
    FinalError,
}

#[derive(Debug)]
pub struct ChunkHeader {
    /// The kind of chunk - message, open or close
    pub message_type: ChunkMessageType,
    /// The chunk type - C == intermediate, F = the final chunk, A = the final chunk when aborting
    pub chunk_type: ChunkType,
    /// The size of the chunk (message) including the header
    pub message_size: UInt32,
    /// Secure channel id
    pub secure_channel_id: UInt32,
    /// valid flag
    pub is_valid: bool,
}

impl BinaryEncoder<ChunkHeader> for ChunkHeader {
    fn byte_len(&self) -> usize {
        CHUNK_HEADER_SIZE
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        if !self.is_valid {
            error!("Cannot write an invalid type");
            return Ok(0);
        }

        let message_type = match self.message_type {
            ChunkMessageType::Message => { CHUNK_MESSAGE }
            ChunkMessageType::OpenSecureChannel => {
                debug!("Encoding a OPEN message");
                OPEN_SECURE_CHANNEL_MESSAGE
            }
            ChunkMessageType::CloseSecureChannel => {
                debug!("Encoding a CLOSE message");
                CLOSE_SECURE_CHANNEL_MESSAGE
            }
        };

        let chunk_type: u8 = match self.chunk_type {
            ChunkType::Intermediate => { CHUNK_INTERMEDIATE }
            ChunkType::Final => { CHUNK_FINAL }
            ChunkType::FinalError => { CHUNK_FINAL_ERROR }
        };

        let mut size = 0;
        size += process_encode_io_result(stream.write(&message_type))?;
        size += write_u8(stream, chunk_type)?;
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
            ChunkMessageType::Message
        } else if message_type_code == OPEN_SECURE_CHANNEL_MESSAGE {
            ChunkMessageType::OpenSecureChannel
        } else if message_type_code == CLOSE_SECURE_CHANNEL_MESSAGE {
            ChunkMessageType::CloseSecureChannel
        } else {
            debug!("Invalid message code");
            is_valid = false;
            ChunkMessageType::Message
        };

        let chunk_type_code = read_u8(stream)?;
        let chunk_type = match chunk_type_code {
            CHUNK_FINAL => { ChunkType::Final }
            CHUNK_INTERMEDIATE => { ChunkType::Intermediate }
            CHUNK_FINAL_ERROR => { ChunkType::FinalError }
            _ => {
                debug!("Invalid chunk type");
                is_valid = false;
                ChunkType::FinalError
            }
        };

        let message_size = read_u32(stream)?;
        let secure_channel_id = read_u32(stream)?;

        Ok(ChunkHeader {
            message_type: message_type,
            chunk_type: chunk_type,
            message_size: message_size,
            secure_channel_id: secure_channel_id,
            is_valid: is_valid,
        })
    }
}

impl ChunkHeader {}

/// Chunk info provides some basic information gleaned from reading the chunk such as offsets into
/// the chunk and so on.
#[derive(Debug, Clone, PartialEq)]
pub struct ChunkInfo {
    // Chunks either have an asymmetric or symmetric security header
    pub security_header: SecurityHeader,
    /// Byte offset to sequence header
    pub sequence_header_offset: usize,
    /// Sequence header information
    pub sequence_header: SequenceHeader,
    /// Byte offset to actual message body
    pub body_offset: usize,
    /// Length of message body
    pub body_length: usize,
    /// Byte offset to padding / signature
    pub padding_offset: usize,
}

impl ChunkInfo {
    pub fn new(chunk: &Chunk, _: &SecureChannelToken) -> std::result::Result<ChunkInfo, StatusCode> {
        let mut chunk_body_stream = Cursor::new(&chunk.chunk_body);

        // Read the security header
        let security_header = if chunk.is_open_secure_channel() {
            let result = AsymmetricSecurityHeader::decode(&mut chunk_body_stream);
            if result.is_err() {
                error!("chunk_info() can't decode asymmetric security_header, {:?}", result.unwrap_err());
                return Err(BAD_COMMUNICATION_ERROR)
            }
            let security_header = result.unwrap();

            let security_policy = if security_header.security_policy_uri.is_null() {
                SecurityPolicy::None
            } else {
                SecurityPolicy::from_uri(&security_header.security_policy_uri.as_ref())
            };

            match security_policy {
                SecurityPolicy::Unknown => {
                    error!("Security policy of chunk is unsupported, policy = {:?}", security_header.security_policy_uri);
                    return Err(BAD_SECURITY_POLICY_REJECTED);
                }
                _ => {
                    // Anything related to policy can be worked out here
                }
            }
            SecurityHeader::Asymmetric(security_header)
        } else {
            let result = SymmetricSecurityHeader::decode(&mut chunk_body_stream);
            if result.is_err() {
                error!("chunk_info() can't decode symmetric security_header, {:?}", result.unwrap_err());
                return Err(BAD_COMMUNICATION_ERROR)
            }
            SecurityHeader::Symmetric(result.unwrap())
        };

        /// TODO compare policy to secure_channel_token if it's supplied - must match

        let sequence_header_offset = chunk_body_stream.position();
        let sequence_header_result = SequenceHeader::decode(&mut chunk_body_stream);
        if sequence_header_result.is_err() {
            error!("Cannot decode sequence header {:?}", sequence_header_result.unwrap_err());
            return Err(BAD_COMMUNICATION_ERROR);
        }
        let sequence_header = sequence_header_result.unwrap();

        // Read Body
        let body_offset = chunk_body_stream.position();

        // All of what follows is the message body
        let body_length = chunk.chunk_body.len() as u64 - body_offset;

        // Complex OPA UA calculation
        // TODO calculate max_body_size based on security policy
        // MaxBodySize = PlainTextBlockSize * Floor((MessageChunkSize –   HeaderSize – SignatureSize - 1)/CipherTextBlockSize) –    SequenceHeaderSize;

        // Padding and signature offset
        let padding_offset = body_offset + body_length;

        let chunk_info = ChunkInfo {
            security_header: security_header,
            sequence_header_offset: sequence_header_offset as usize,
            sequence_header: sequence_header,
            body_offset: body_offset as usize,
            body_length: body_length as usize,
            padding_offset: padding_offset as usize,
        };

        Ok(chunk_info)
    }
}

/// A chunk holds a part or the whole of a message. The chunk may be signed and encrypted. To
/// extract the message may require one or more chunks.
#[derive(Debug)]
pub struct Chunk {
    /// Header for this chunk
    pub chunk_header: ChunkHeader,
    pub chunk_body: Vec<u8>,
}

impl BinaryEncoder<Chunk> for Chunk {
    fn byte_len(&self) -> usize {
        let mut size = self.chunk_header.byte_len();
        size += self.chunk_body.len();
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = self.chunk_header.encode(stream)?;
        let result = stream.write(&self.chunk_body);
        if result.is_err() {
            Err(BAD_ENCODING_ERROR)
        } else {
            size += self.chunk_body.len();
            Ok(size)
        }
    }

    fn decode<S: Read>(in_stream: &mut S) -> EncodingResult<Self> {
        let chunk_header_result = ChunkHeader::decode(in_stream);
        if chunk_header_result.is_err() {
            error!("Cannot decode chunk header {:?}", chunk_header_result.unwrap_err());
            return Err(BAD_COMMUNICATION_ERROR);
        }

        let chunk_header = chunk_header_result.unwrap();
        if !chunk_header.is_valid {
            return Err(BAD_TCP_MESSAGE_TYPE_INVALID);
        }

        let buffer_size = chunk_header.message_size as usize - CHUNK_HEADER_SIZE;
        let mut chunk_body = vec![0u8; buffer_size];
        let _ = in_stream.read_exact(&mut chunk_body);

        Ok(Chunk {
            chunk_header: chunk_header,
            chunk_body: chunk_body,
        })
    }
}

impl Chunk {
    /// Calculates how large a plain text can be to fix the inside of a chunk of a particular size.
    /// This requires calculating the size of the header, the signature, padding etc. and deducting it
    /// to reveal the message size
    pub fn message_size_from_chunk_size(message_type: ChunkMessageType, secure_channel_token: &SecureChannelToken, max_chunk_size: usize) -> usize {
        if max_chunk_size < 8192 {
            panic!("max chunk size cannot be less than minimum in the spec");
        }

        let mut chunk_size = CHUNK_HEADER_SIZE;
        chunk_size += secure_channel_token.make_security_header(message_type).byte_len();
        chunk_size += (SequenceHeader { sequence_number: 0, request_id: 0 }).byte_len();

        // 1 byte == most padding
        let (padding_size, extra_padding_size) = secure_channel_token.calc_chunk_padding(1);
        if padding_size > 0 {
            chunk_size += 1 + padding_size as usize;
        }
        if extra_padding_size > 0 {
            chunk_size += 1 + extra_padding_size as usize;
        }

        // signature length
        chunk_size += secure_channel_token.signature_size();

        // Message size is what's left
        max_chunk_size - chunk_size
    }

    pub fn new(sequence_number: UInt32, request_id: UInt32, message_type: ChunkMessageType, chunk_type: ChunkType, secure_channel_token: &SecureChannelToken, data: &[u8]) -> Result<Chunk, StatusCode> {
        // security header depends on message type
        let security_header = secure_channel_token.make_security_header(message_type);
        let sequence_header = SequenceHeader { sequence_number, request_id };

        // Calculate the chunk body size
        let mut chunk_body_size = 0;
        chunk_body_size += security_header.byte_len();
        chunk_body_size += sequence_header.byte_len();
        chunk_body_size += data.len();
        // Test if padding is required
        let (padding_size, extra_padding_size) = secure_channel_token.calc_chunk_padding(data.len());
        if padding_size > 0 {
            chunk_body_size += 1 + padding_size as usize;
        }
        if extra_padding_size > 0 {
            chunk_body_size += 1 + extra_padding_size as usize;
        }

        let mut stream = Cursor::new(vec![0u8; chunk_body_size]);
        // write security header
        let _ = security_header.encode(&mut stream);
        // write sequence header
        let _ = sequence_header.encode(&mut stream);
        // write message
        let _ = stream.write(data);
        // write padding byte?
        if padding_size > 0u8 {
            // Padding size
            let _ = write_u8(&mut stream, padding_size)?;
            // Padding bytes
            for _ in 0..padding_size {
                let _ = write_u8(&mut stream, 0u8)?;
            }
            if extra_padding_size > 0u8 {
                let _ = write_u8(&mut stream, extra_padding_size)?;
                for _ in 0..extra_padding_size {
                    let _ = write_u8(&mut stream, 0u8)?;
                }
            }
        }

        // TODO encrypt
        // TODO calculate signature
        // write signature

        let message_size = (CHUNK_HEADER_SIZE + chunk_body_size) as u32;
        debug!("Creating a chunk with a size of {}", message_size);

        let secure_channel_id = secure_channel_token.secure_channel_id;
        let chunk_header = ChunkHeader {
            message_type,
            chunk_type,
            message_size,
            secure_channel_id,
            is_valid: true,
        };

        Ok(Chunk {
            chunk_header: chunk_header,
            chunk_body: stream.into_inner(),
        })
    }

    pub fn is_open_secure_channel(&self) -> bool {
        self.chunk_header.message_type == ChunkMessageType::OpenSecureChannel
    }

    pub fn chunk_info(&self, secure_channel_token: &SecureChannelToken) -> std::result::Result<ChunkInfo, StatusCode> {
        ChunkInfo::new(self, secure_channel_token)
    }
}
