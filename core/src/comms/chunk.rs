use std;
use std::io::{Read, Write, Result, Cursor};
use std::fmt;

use types::*;
use services::*;

const CHUNK_HEADER_SIZE: usize = 12;

#[derive(Debug, PartialEq)]
pub enum ChunkMessageType {
    Message,
    OpenSecureChannel,
    CloseSecureChannel
}

#[derive(Debug, PartialEq)]
pub enum ChunkType {
    /// Intermediate chunk
    Intermediate,
    /// Final chunk
    Final,
    /// Abort
    FinalError,
}

#[derive(Debug)]
pub struct ChunkHeader {
    /// MSG, OPN, CLO
    pub message_type: ChunkMessageType,
    /// C == intermediate, F = the final chunk, A = the final chunk when aborting
    pub is_final: ChunkType,
    /// The size of the chunk (message) including the header
    pub message_size: UInt32,
    /// Secure channel id
    pub secure_channel_id: UInt32,
    /// valid flag
    pub is_valid: bool,
}

const HEADER_MSG: [u8; 3] = [b'M', b'S', b'G'];
const HEADER_OPN: [u8; 3] = [b'O', b'P', b'N'];
const HEADER_CLO: [u8; 3] = [b'C', b'L', b'O'];

const CHUNK_FINAL: u8 = b'F';
const CHUNK_INTERMEDIATE: u8 = b'C';
const CHUNK_FINAL_ERROR: u8 = b'A';

impl BinaryEncoder<ChunkHeader> for ChunkHeader {
    fn byte_len(&self) -> usize {
        CHUNK_HEADER_SIZE
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        if !self.is_valid {
            error!("Cannot write an invalid type");
            return Ok(0);
        }

        let message_type: [u8; 3] = match self.message_type {
            ChunkMessageType::Message => { HEADER_MSG },
            ChunkMessageType::OpenSecureChannel => { HEADER_OPN },
            ChunkMessageType::CloseSecureChannel => { HEADER_CLO }
        };

        let is_final: u8 = match self.is_final {
            ChunkType::Intermediate => { CHUNK_INTERMEDIATE }
            ChunkType::Final => { CHUNK_FINAL },
            ChunkType::FinalError => { CHUNK_FINAL_ERROR },
        };

        let mut size = 0;
        size += stream.write(&message_type)?;
        size += write_u8(stream, is_final)?;
        size += write_u32(stream, self.message_size)?;
        size += write_u32(stream, self.secure_channel_id)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<ChunkHeader> {
        let mut is_valid = true;

        let mut message_type_code: [u8; 3] = [0, 0, 0];
        stream.read_exact(&mut message_type_code)?;
        let message_type = if message_type_code == HEADER_MSG {
            ChunkMessageType::Message
        } else if message_type_code == HEADER_OPN {
            ChunkMessageType::OpenSecureChannel
        } else if message_type_code == HEADER_CLO {
            ChunkMessageType::CloseSecureChannel
        } else {
            debug!("Invalid message code");
            is_valid = false;
            ChunkMessageType::Message
        };

        let is_final_code = read_u8(stream)?;
        let is_final = match is_final_code {
            CHUNK_FINAL => { ChunkType::Final },
            CHUNK_INTERMEDIATE => { ChunkType::Intermediate },
            CHUNK_FINAL_ERROR => { ChunkType::FinalError },
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
            is_final: is_final,
            message_size: message_size,
            secure_channel_id: secure_channel_id,
            is_valid: is_valid,
        })
    }
}

impl ChunkHeader {}

#[derive(Debug)]
pub struct ChunkInfo {
    /// Security header
    pub security_header: SecurityHeader,
    /// Byte offset to sequence header
    pub sequence_header_offset: usize,
    /// Sequence header information
    pub sequence_header: SequenceHeader,
    /// Byte offset to actual message body
    pub body_offset: usize,
    /// Length of message body
    pub body_length: usize,
    /// Byte offset to signature
    pub signature_offset: usize,
}

#[derive(Debug, PartialEq)]
pub enum SupportedMessage {
    Invalid(ObjectId),
    OpenSecureChannelRequest(OpenSecureChannelRequest),
    OpenSecureChannelResponse(OpenSecureChannelResponse),
    CloseSecureChannelRequest(CloseSecureChannelRequest),
    CloseSecureChannelResponse(CloseSecureChannelResponse),
}

impl BinaryEncoder<SupportedMessage> for SupportedMessage {
    fn byte_len(&self) -> usize {
        match *self {
            SupportedMessage::Invalid(object_id) => {
                panic!("Unsupported message {:?}", object_id);
            },
            SupportedMessage::OpenSecureChannelRequest(ref value) => value.byte_len(),
            SupportedMessage::OpenSecureChannelResponse(ref value) => value.byte_len(),
            SupportedMessage::CloseSecureChannelRequest(ref value) => value.byte_len(),
            SupportedMessage::CloseSecureChannelResponse(ref value) => value.byte_len(),
        }
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        match *self {
            SupportedMessage::Invalid(object_id) => {
                panic!("Unsupported message {:?}", object_id);
            },
            SupportedMessage::OpenSecureChannelRequest(ref value) => value.encode(stream),
            SupportedMessage::OpenSecureChannelResponse(ref value) => value.encode(stream),
            SupportedMessage::CloseSecureChannelRequest(ref value) => value.encode(stream),
            SupportedMessage::CloseSecureChannelResponse(ref value) => value.encode(stream),
        }
    }

    fn decode(stream: &mut Read) -> Result<SupportedMessage> {
        // THIS WILL NOT DO ANYTHING
        panic!("Cannot decode a stream to a supported message type");
    }
}

impl SupportedMessage {
    pub fn node_id(&self) -> NodeId {
        match *self {
            SupportedMessage::Invalid(object_id) => {
                panic!("Unsupported message {:?}", object_id);
            },
            SupportedMessage::OpenSecureChannelRequest(ref value) => value.node_id(),
            SupportedMessage::OpenSecureChannelResponse(ref value) => value.node_id(),
            SupportedMessage::CloseSecureChannelRequest(ref value) => value.node_id(),
            SupportedMessage::CloseSecureChannelResponse(ref value) => value.node_id(),
        }
    }

    pub fn chunk_message_type(&self) -> ChunkMessageType {
        match *self {
            SupportedMessage::Invalid(object_id) => {
                panic!("Unsupported message {:?}", object_id);
            },
            SupportedMessage::OpenSecureChannelRequest(_) => ChunkMessageType::OpenSecureChannel,
            SupportedMessage::OpenSecureChannelResponse(_) => ChunkMessageType::OpenSecureChannel,
            SupportedMessage::CloseSecureChannelRequest(_) => ChunkMessageType::CloseSecureChannel,
            SupportedMessage::CloseSecureChannelResponse(_) => ChunkMessageType::CloseSecureChannel,
        }
    }
}

#[derive(Debug)]
pub struct SecurityHeader {
    pub security_policy_uri: String,
    pub sender_certificate: Vec<u8>,
    pub receiver_certificate_thumbprint: Vec<u8>,
}

impl BinaryEncoder<SecurityHeader> for SecurityHeader {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += 4; // security_policy_uri
        size += self.security_policy_uri.len();
        size += 4; // sender_certificate
        size += self.sender_certificate.len();
        size += 4; // receiver_certificate_thumbprint
        size += self.receiver_certificate_thumbprint.len();
        size
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size = 0;
        size += write_i32(stream, self.security_policy_uri.len() as Int32)?;
        size += stream.write(self.security_policy_uri.as_bytes())?;
        size += write_i32(stream, self.sender_certificate.len() as i32)?;
        size += stream.write(&self.sender_certificate)?;
        size += write_i32(stream, self.receiver_certificate_thumbprint.len() as i32)?;
        size += stream.write(&self.receiver_certificate_thumbprint)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<SecurityHeader> {
        let mut security_policy_uri = String::new();
        {
            // TODO this can be done by ByteString
            let security_policy_uri_length = read_i32(stream)?;
            if security_policy_uri_length > 0 {
                let buf_len = security_policy_uri_length;
                let mut buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
                buf.resize(buf_len as usize, 0u8);
                stream.read_exact(&mut buf)?;
                security_policy_uri = String::from_utf8(buf).unwrap()
            }
        }

        let mut sender_certificate: Vec<u8> = Vec::new();
        {
            let sender_certificate_length = read_i32(stream)?;
            if sender_certificate_length > 0 {
                // TODO validate sender_certificate_length < MaxCertificateSize
                sender_certificate.resize(sender_certificate_length as usize, 0u8);
                stream.read_exact(&mut sender_certificate)?;
            }
        }

        let mut receiver_certificate_thumbprint: Vec<u8> = Vec::new();
        {
            let receiver_certificate_thumbprint_length = read_i32(stream)?;
            if receiver_certificate_thumbprint_length > 0 {
                // TODO validate receiver_certificate_thumbprint_length == 20
                receiver_certificate_thumbprint.resize(receiver_certificate_thumbprint_length as usize, 0u8);
                stream.read_exact(&mut receiver_certificate_thumbprint)?;
            }
        }

        Ok(SecurityHeader {
            security_policy_uri: security_policy_uri,
            sender_certificate: sender_certificate,
            receiver_certificate_thumbprint: receiver_certificate_thumbprint
        })
    }
}

#[derive(Debug)]
pub struct SequenceHeader {
    pub sequence_number: UInt32,
    pub request_id: UInt32,
}

impl BinaryEncoder<SequenceHeader> for SequenceHeader {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;
        size += write_u32(stream, self.sequence_number)?;
        size += write_u32(stream, self.request_id)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<SequenceHeader> {
        let sequence_number = read_u32(stream)?;
        let request_id = read_u32(stream)?;
        Ok(SequenceHeader {
            sequence_number: sequence_number,
            request_id: request_id,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum SecurityPolicy {
    Unknown,
    None,
    Basic128Rsa15,
    Basic256,
    Basic256Sha256,
}

const SECURITY_POLICY_NONE: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#None";
const SECURITY_POLICY_BASIC128RSA15: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
const SECURITY_POLICY_BASIC256: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
const SECURITY_POLICY_BASIC256SHA256: &'static str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";

impl SecurityPolicy {
    pub fn to_uri(&self) -> &'static str {
        match *self {
            SecurityPolicy::None => SECURITY_POLICY_NONE,
            SecurityPolicy::Basic128Rsa15 => SECURITY_POLICY_BASIC128RSA15,
            SecurityPolicy::Basic256 => SECURITY_POLICY_BASIC256,
            SecurityPolicy::Basic256Sha256 => SECURITY_POLICY_BASIC256SHA256,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a uri");
            }
        }
    }

    pub fn from_uri(uri: &String) -> SecurityPolicy {
        let uri = uri.as_str();
        match uri {
            SECURITY_POLICY_NONE => {
                SecurityPolicy::None
            },
            SECURITY_POLICY_BASIC128RSA15 => {
                SecurityPolicy::Basic128Rsa15
            },
            SECURITY_POLICY_BASIC256 => {
                SecurityPolicy::Basic256
            },
            SECURITY_POLICY_BASIC256SHA256 => {
                SecurityPolicy::Basic256Sha256
            }
            _ => {
                error!("Specified security policy {} is not recognized", uri);
                SecurityPolicy::Unknown
            }
        }
    }
}

pub struct SecureChannelInfo {
    pub security_policy: SecurityPolicy,
    pub secure_channel_id: UInt32,
}

/// A chunk holds a part or the whole of a message. The chunk may be signed and encrypted. To
/// extract the message may require one or more chunks.
pub struct Chunk {
    /// Header for this chunk
    pub chunk_header: ChunkHeader,
    pub chunk_body: Vec<u8>,
}

impl fmt::Debug for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let chunk_info = self.chunk_info(Option::None).unwrap();
        let mut hex_dump = String::with_capacity(self.chunk_body.len() * 3);
        for b in &self.chunk_body {
            hex_dump.push_str(format!("{:02x},", b).as_str());
        }
        write!(f, "Chunk Header - {:?}\nChunk Info - {:?}\nChunk Body: {}", self.chunk_header, chunk_info, hex_dump, )
    }
}

impl Chunk {
    pub fn decode(in_stream: &mut Read) -> std::result::Result<Chunk, &'static StatusCode> {
        let chunk_header_result = ChunkHeader::decode(in_stream);
        if chunk_header_result.is_err() {
            return Err(&BAD_COMMUNICATION_ERROR);
        }

        let chunk_header = chunk_header_result.unwrap();
        if !chunk_header.is_valid {
            return Err(&BAD_TCP_MESSAGE_TYPE_INVALID);
        }

        let buffer_size = chunk_header.message_size as usize - CHUNK_HEADER_SIZE;
        let mut chunk_body = vec![0u8; buffer_size];
        in_stream.read_exact(&mut chunk_body);

        Ok(Chunk {
            chunk_header: chunk_header,
            chunk_body: chunk_body,
        })
    }

    fn debug_stream(stream: &Cursor<&Vec<u8>>, buf: &[u8]) {
        let pos = stream.position() as usize;
        debug!("Stream position = {}, bytes = {:02x},{:02x},{:02x},{:02x}", pos, buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
    }

    pub fn chunk_info(&self, _: Option<&mut SecureChannelInfo>) -> std::result::Result<ChunkInfo, &'static StatusCode> {
        let mut chunk_stream = Cursor::new(&self.chunk_body);

        // Message::debug_stream(&message_stream, &self.message_body);
        let security_header_result = SecurityHeader::decode(&mut chunk_stream);
        if security_header_result.is_err() {
            return Err(&BAD_COMMUNICATION_ERROR)
        }
        let security_header = security_header_result.unwrap();

        let security_policy = SecurityPolicy::from_uri(&security_header.security_policy_uri);
        if security_policy != SecurityPolicy::None {
            return Err(&BAD_SECURITY_POLICY_REJECTED);
        }

        // Message::debug_stream(&message_stream, &self.message_body);
        let sequence_header_offset = chunk_stream.position();
        let sequence_header_result = SequenceHeader::decode(&mut chunk_stream);
        if sequence_header_result.is_err() {
            return Err(&BAD_COMMUNICATION_ERROR);
        }
        let sequence_header = sequence_header_result.unwrap();

        // Message::debug_stream(&message_stream, &self.message_body);

        // Read Body
        let body_offset = chunk_stream.position();
        let body_length = if security_policy == SecurityPolicy::None {
            // All of what follows is the message body
            self.chunk_body.len() as u64 - body_offset
        } else {
            /// Complex OPA UA calculation
            /// MaxBodySize = PlainTextBlockSize * Floor((MessageChunkSize –   HeaderSize – SignatureSize - 1)/CipherTextBlockSize) –    SequenceHeaderSize;
            unimplemented!();
        };

        // TODO
        let signature_offset = body_offset + body_length;

        let message_info = ChunkInfo {
            security_header: security_header,
            sequence_header_offset: sequence_header_offset as usize,
            sequence_header: sequence_header,
            body_offset: body_offset as usize,
            body_length: body_length as usize,
            signature_offset: signature_offset as usize,
        };

        Ok(message_info)
    }
}

pub struct Chunker {
    pub last_encoded_sequence_number: UInt32,
    pub last_decoded_sequence_number: UInt32,
}

impl Chunker {
    pub fn new() -> Chunker {
        Chunker {
            last_encoded_sequence_number: 0,
            last_decoded_sequence_number: 0,
        }
    }

    pub fn encode(&mut self, request_id: UInt32, secure_channel_info: &mut SecureChannelInfo, message: &SupportedMessage) -> std::result::Result<Vec<Box<Chunk>>, ()> {
        // TODO multiple chunks

        // External values
        let sequence_number = self.last_encoded_sequence_number + 1;
        self.last_encoded_sequence_number = sequence_number;
        let secure_channel_id = secure_channel_info.secure_channel_id;

        debug!("Creating a chunk for secure channel id {}, sequence id {}", secure_channel_id, sequence_number);

        let message_type = message.chunk_message_type();
        let node_id = message.node_id();

        let is_first_chunk = true;
        let is_last_chunk = true;
        let is_final = if is_last_chunk { ChunkType::Final } else { ChunkType::Intermediate };

        // Calculate the chunk body size
        let mut chunk_body_size = 0;
        if is_first_chunk {
            // Write a node id
            chunk_body_size += node_id.byte_len();
        }
        // write security header
        let security_header = SecurityHeader {
            security_policy_uri: SECURITY_POLICY_NONE.to_string(),
            sender_certificate: Vec::new(),
            receiver_certificate_thumbprint: Vec::new(),
        };
        let sequence_header = SequenceHeader {
            sequence_number: sequence_number,
            request_id: request_id,
        };

        chunk_body_size += security_header.byte_len();
        chunk_body_size += sequence_header.byte_len();
        chunk_body_size += message.byte_len();
        // TODO encrypted message size
        // TODO padding size
        // TODO signature size

        let message_size = (CHUNK_HEADER_SIZE + chunk_body_size) as u32;

        debug!("Creating a chunk with a size of {}", message_size);

        let chunk_header = ChunkHeader {
            message_type: message_type,
            is_final: is_final,
            message_size: message_size,
            secure_channel_id: secure_channel_id,
            is_valid: true,
        };

        let mut stream = Cursor::new(vec![0u8; chunk_body_size]);
        // Write a node id for the first chunk
        if is_first_chunk {
            debug!("Encoding node id");
            node_id.encode(&mut stream);
        }
        // write security header
        debug!("Encoding security header");
        security_header.encode(&mut stream);
        // write sequence header
        debug!("Encoding sequence header");
        sequence_header.encode(&mut stream);
        // write message
        debug!("Encoding message");
        message.encode(&mut stream);

        // TODO write padding
        // TODO encrypt
        // TODO calculate signature
        // TODO write signature

        // Now the chunk is made and can be added to the result
        debug!("Returning chunk");
        let chunk = Box::new(Chunk {
            chunk_header: chunk_header,
            chunk_body: stream.into_inner(),
        });
        let chunks = vec![chunk];

        Ok(chunks)
    }

    /// This function extracts the message from one or more chunks. The chunks should have been
    pub fn decode(&mut self, chunks: &Vec<&Chunk>, expected_id: Option<NodeId>) -> std::result::Result<SupportedMessage, &'static StatusCode> {
        if chunks.len() != 1 {
            // TODO more than one chunk is not supported
            // Chunk error
            error!("Only one chunk is supported");
            return Err(&BAD_UNEXPECTED_ERROR);
        }

        let chunk = &chunks[0];
        let chunk_info = chunk.chunk_info(Option::None)?;

        // Check the sequence id - should be larger than the last one decoded
        if chunk_info.sequence_header.sequence_number <= self.last_decoded_sequence_number {
            return Err(&BAD_SEQUENCE_NUMBER_INVALID);
        }
        self.last_decoded_sequence_number = chunk_info.sequence_header.sequence_number;

        let body_start = chunk_info.body_offset;
        let body_end = body_start + chunk_info.body_length;
        let chunk_body = &chunk.chunk_body[body_start..body_end];

        // TODO when multiple chunks are supported, probably the easiest way is some
        // kind of cursor that sits on top of the message bodies of each, decrypting the msg if
        // necessary
        let mut chunk_body_stream = &mut Cursor::new(chunk_body);

        // The extension object prefix is just the node id. A point the spec rather unhelpfully doesn't
        // elaborate on. Probably because people enjoy debugging why the stream pos is out by 1 byte
        // for hours.
        let node_id = NodeId::decode(&mut chunk_body_stream);
        if node_id.is_err() {
            error!("The node id could not be read from the stream {:?}", node_id);
            return Err(&BAD_UNEXPECTED_ERROR);
        }
        let node_id = node_id.unwrap();
        let valid_node_id = if node_id.namespace != 0 || !node_id.is_numeric() {
            // Must be ns 0 and numeric
            false
        } else if expected_id.is_some() {
            expected_id.unwrap() == node_id
        } else {
            false
        };
        if !valid_node_id {
            error!("The node id read from the stream was accepted in this context {:?}", node_id);
            return Err(&BAD_UNEXPECTED_ERROR);
        }

        // Now the payload. The node id of the prefix allows us to recognize it.
        if let Ok(object_id) = node_id.as_object_id() {
            let decoded_message = match object_id {
                ObjectId::OpenSecureChannelRequest_Encoding_DefaultBinary => {
                    if let Ok(message) = OpenSecureChannelRequest::decode(&mut chunk_body_stream) {
                        SupportedMessage::OpenSecureChannelRequest(message)
                    } else {
                        SupportedMessage::Invalid(object_id)
                    }
                },
                ObjectId::CloseSecureChannelRequest_Encoding_DefaultBinary => {
                    if let Ok(message) = CloseSecureChannelRequest::decode(&mut chunk_body_stream) {
                        SupportedMessage::CloseSecureChannelRequest(message)
                    } else {
                        SupportedMessage::Invalid(object_id)
                    }
                }
                _ => { SupportedMessage::Invalid(object_id) }
            };
            if let SupportedMessage::Invalid(_) = decoded_message {
                return Err(&BAD_TCP_MESSAGE_TYPE_INVALID);
            }
            return Ok(decoded_message)
        } else {
            return Err(&BAD_TCP_MESSAGE_TYPE_INVALID);
        }
    }

    pub fn decode_open_secure_channel_request(&mut self, chunks: &Vec<&Chunk>) -> std::result::Result<OpenSecureChannelRequest, &'static StatusCode> {
        let expected_node_id = NodeId::from_object_id(ObjectId::OpenSecureChannelRequest_Encoding_DefaultBinary);
        let result = self.decode(chunks, Some(expected_node_id))?;
        match result {
            SupportedMessage::OpenSecureChannelRequest(message) => {
                Ok(message)
            },
            _ => {
                panic!("Should not have received anything but OpenSecureChannelRequest here");
            }
        }
    }

    pub fn decode_close_secure_channel_request(&mut self, chunks: &Vec<&Chunk>) -> std::result::Result<CloseSecureChannelRequest, &'static StatusCode> {
        let expected_node_id = NodeId::from_object_id(ObjectId::CloseSecureChannelRequest_Encoding_DefaultBinary);
        let result = self.decode(chunks, Some(expected_node_id))?;
        match result {
            SupportedMessage::CloseSecureChannelRequest(message) => {
                Ok(message)
            },
            _ => {
                panic!("Should not have received anything but CloseSecureChannelRequest here");
            }
        }
    }
}