use std;
use std::io::{Read, Write, Result, Cursor};

use debug::*;
use types::*;
use comms::*;

use services::secure_channel::*;

const CHUNK_HEADER_SIZE: usize = 12;

#[derive(Debug, Clone, PartialEq)]
pub enum ChunkMessageType {
    Message,
    OpenSecureChannel,
    CloseSecureChannel
}

#[derive(Debug, Clone, PartialEq)]
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
    pub chunk_type: ChunkType,
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

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        if !self.is_valid {
            error!("Cannot write an invalid type");
            return Ok(0);
        }

        let message_type: [u8; 3] = match self.message_type {
            ChunkMessageType::Message => { HEADER_MSG },
            ChunkMessageType::OpenSecureChannel => { HEADER_OPN },
            ChunkMessageType::CloseSecureChannel => { HEADER_CLO }
        };

        let chunk_type: u8 = match self.chunk_type {
            ChunkType::Intermediate => { CHUNK_INTERMEDIATE }
            ChunkType::Final => { CHUNK_FINAL },
            ChunkType::FinalError => { CHUNK_FINAL_ERROR },
        };

        let mut size = 0;
        size += stream.write(&message_type)?;
        size += write_u8(stream, chunk_type)?;
        size += write_u32(stream, self.message_size)?;
        size += write_u32(stream, self.secure_channel_id)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<Self> {
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

        let chunk_type_code = read_u8(stream)?;
        let chunk_type = match chunk_type_code {
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
            chunk_type: chunk_type,
            message_size: message_size,
            secure_channel_id: secure_channel_id,
            is_valid: is_valid,
        })
    }
}

impl ChunkHeader {}

#[derive(Debug, Clone, PartialEq)]
pub struct ChunkInfo {
    /// Node id, if present (first chunk only of a MSG)
    pub node_id: Option<NodeId>,
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
    /// Byte offset to signature
    pub signature_offset: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityHeader {
    Asymmetric(AsymmetricSecurityHeader),
    Symmetric(SymmetricSecurityHeader),
}

impl BinaryEncoder<SecurityHeader> for SecurityHeader {
    fn byte_len(&self) -> usize {
        match *self {
            SecurityHeader::Asymmetric(ref value) => { value.byte_len() },
            SecurityHeader::Symmetric(ref value) => { value.byte_len() },
        }
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        match *self {
            SecurityHeader::Asymmetric(ref value) => { value.encode(stream) },
            SecurityHeader::Symmetric(ref value) => { value.encode(stream) },
        }
    }

    fn decode<S: Read>(stream: &mut S) -> Result<Self> {
        unimplemented!();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SymmetricSecurityHeader {
    pub token_id: UInt32,
}

impl BinaryEncoder<SymmetricSecurityHeader> for SymmetricSecurityHeader {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        Ok(self.token_id.encode(stream)?)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<Self> {
        let token_id = UInt32::decode(stream)?;
        Ok(SymmetricSecurityHeader {
            token_id: token_id
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AsymmetricSecurityHeader {
    pub security_policy_uri: String,
    pub sender_certificate: Vec<u8>,
    pub receiver_certificate_thumbprint: Vec<u8>,
}

impl BinaryEncoder<AsymmetricSecurityHeader> for AsymmetricSecurityHeader {
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

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        let mut size = 0;
        size += write_i32(stream, self.security_policy_uri.len() as Int32)?;
        size += stream.write(self.security_policy_uri.as_bytes())?;
        size += write_i32(stream, self.sender_certificate.len() as i32)?;
        size += stream.write(&self.sender_certificate)?;
        size += write_i32(stream, self.receiver_certificate_thumbprint.len() as i32)?;
        size += stream.write(&self.receiver_certificate_thumbprint)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<Self> {
        let mut security_policy_uri = String::new();
        {
            // TODO this can be done by ByteString
            let security_policy_uri_length = read_i32(stream)?;
            // debug!("SecurityHeader::security_policy_uri_length = {:?}", security_policy_uri_length);

            if security_policy_uri_length > 0 {
                let buf_len = security_policy_uri_length;
                let mut buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
                buf.resize(buf_len as usize, 0u8);
                stream.read_exact(&mut buf)?;
                security_policy_uri = String::from_utf8(buf).unwrap()
            }
        }
        // debug!("SecurityHeader::security_policy_uri = {:?}", security_policy_uri);

        let mut sender_certificate: Vec<u8> = Vec::new();
        {
            let sender_certificate_length = read_i32(stream)?;
            // debug!("SecurityHeader::sender_certificate_length = {:?}", sender_certificate_length);
            if sender_certificate_length > 0 {
                // TODO validate sender_certificate_length < MaxCertificateSize
                sender_certificate.resize(sender_certificate_length as usize, 0u8);
                stream.read_exact(&mut sender_certificate)?;
            }
        }
        // debug!("SecurityHeader::sender_certificate = {:?}", sender_certificate);

        let mut receiver_certificate_thumbprint: Vec<u8> = Vec::new();
        {
            let receiver_certificate_thumbprint_length = read_i32(stream)?;
            // debug!("SecurityHeader::receiver_certificate_thumbprint_length = {:?}", receiver_certificate_thumbprint_length);
            if receiver_certificate_thumbprint_length > 0 {
                // TODO validate receiver_certificate_thumbprint_length == 20
                receiver_certificate_thumbprint.resize(receiver_certificate_thumbprint_length as usize, 0u8);
                stream.read_exact(&mut receiver_certificate_thumbprint)?;
            }
        }
        // debug!("SecurityHeader::receiver_certificate_thumbprint = {:?}", receiver_certificate_thumbprint);

        Ok(AsymmetricSecurityHeader {
            security_policy_uri: security_policy_uri,
            sender_certificate: sender_certificate,
            receiver_certificate_thumbprint: receiver_certificate_thumbprint
        })
    }
}

impl AsymmetricSecurityHeader {
    pub fn none() -> AsymmetricSecurityHeader {
        AsymmetricSecurityHeader {
            security_policy_uri: SecurityPolicy::None.to_uri().to_string(),
            sender_certificate: Vec::new(),
            receiver_certificate_thumbprint: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SequenceHeader {
    pub sequence_number: UInt32,
    pub request_id: UInt32,
}

impl BinaryEncoder<SequenceHeader> for SequenceHeader {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> Result<usize> {
        let mut size: usize = 0;
        size += write_u32(stream, self.sequence_number)?;
        size += write_u32(stream, self.request_id)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<Self> {
        let sequence_number = read_u32(stream)?;
        let request_id = read_u32(stream)?;
        Ok(SequenceHeader {
            sequence_number: sequence_number,
            request_id: request_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone)]
pub struct SecureChannelInfo {
    pub security_policy: SecurityPolicy,
    pub secure_channel_id: UInt32,
}

/// A chunk holds a part or the whole of a message. The chunk may be signed and encrypted. To
/// extract the message may require one or more chunks.
#[derive(Debug)]
pub struct Chunk {
    /// Header for this chunk
    pub chunk_header: ChunkHeader,
    pub chunk_body: Vec<u8>,
}

impl Chunk {
    pub fn encode<S: Write>(&self, stream: &mut S) -> std::result::Result<(), &'static StatusCode> {
        // TODO this is a stub
        // TODO impl should be moved to BinaryEncoder
        debug!("Encoding chunk_header");
        let _ = self.chunk_header.encode(stream);
        debug!("Encoding chunk_body");
        let _ = stream.write(&self.chunk_body);
        Ok(())
    }

    pub fn decode<S: Read>(in_stream: &mut S) -> std::result::Result<Chunk, &'static StatusCode> {
        // TODO impl should be moved to BinaryEncoder
        let chunk_header_result = ChunkHeader::decode(in_stream);
        if chunk_header_result.is_err() {
            error!("Cannot decode chunk header {:?}", chunk_header_result.unwrap_err());
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

    pub fn chunk_info(&self, is_first_chunk: bool, secure_channel_info: Option<&mut SecureChannelInfo>) -> std::result::Result<ChunkInfo, &'static StatusCode> {
        {
            debug!("chunk_info() - chunk_body:");
            debug_buffer(&self.chunk_body);
        }

        let mut chunk_body_stream = Cursor::new(&self.chunk_body);

        // Read the security header
        let security_header = if self.chunk_header.message_type == ChunkMessageType::OpenSecureChannel {
            let result = AsymmetricSecurityHeader::decode(&mut chunk_body_stream);
            if result.is_err() {
                error!("chunk_info() can't decode asymmetric security_header, {:?}", result.unwrap_err());
                return Err(&BAD_COMMUNICATION_ERROR)
            }
            let security_header = result.unwrap();
            let security_policy = SecurityPolicy::from_uri(&security_header.security_policy_uri);
            if security_policy != SecurityPolicy::None {
                error!("Security policy of chunk is unsupported, policy = {:?}", security_header.security_policy_uri);
                return Err(&BAD_SECURITY_POLICY_REJECTED);
            }
            SecurityHeader::Asymmetric(security_header)
        } else {
            let result = SymmetricSecurityHeader::decode(&mut chunk_body_stream);
            if result.is_err() {
                error!("chunk_info() can't decode symmetric security_header, {:?}", result.unwrap_err());
                return Err(&BAD_COMMUNICATION_ERROR)
            }
            SecurityHeader::Symmetric(result.unwrap())
        };

        /// TODO compare policy to secure_channel_info if it's supplied - must match

        let sequence_header_offset = chunk_body_stream.position();
        let sequence_header_result = SequenceHeader::decode(&mut chunk_body_stream);
        if sequence_header_result.is_err() {
            error!("Cannot decode sequence header {:?}", sequence_header_result.unwrap_err());
            return Err(&BAD_COMMUNICATION_ERROR);
        }
        let sequence_header = sequence_header_result.unwrap();

        let node_id = if is_first_chunk {
            let node_id_result = NodeId::decode(&mut chunk_body_stream);
            if node_id_result.is_err() {
                error!("chunk_info() can't decode node_id, {:?}", node_id_result.unwrap_err());
                return Err(&BAD_COMMUNICATION_ERROR)
            }
            Some(node_id_result.unwrap())
        } else {
            debug!("chunk_info() is skipping node_id, is_first_chunk = {:?}, message_type = {:?}", is_first_chunk, self.chunk_header.message_type);
            None
        };

        // Read Body
        let body_offset = chunk_body_stream.position();

        // All of what follows is the message body
        let body_length = self.chunk_body.len() as u64 - body_offset;
        // Complex OPA UA calculation
        // TODO calculate max_body_size based on security policy
        // MaxBodySize = PlainTextBlockSize * Floor((MessageChunkSize –   HeaderSize – SignatureSize - 1)/CipherTextBlockSize) –    SequenceHeaderSize;

        // TODO
        let signature_offset = body_offset + body_length;

        let chunk_info = ChunkInfo {
            node_id: node_id,
            security_header: security_header,
            sequence_header_offset: sequence_header_offset as usize,
            sequence_header: sequence_header,

            body_offset: body_offset as usize,
            body_length: body_length as usize,
            signature_offset: signature_offset as usize,
        };
        debug!("chunk_info() = {:#?}", chunk_info);

        Ok(chunk_info)
    }
}

pub struct Chunker {
    pub last_encoded_sequence_number: UInt32,
    pub last_decoded_sequence_number: UInt32,
}

impl Chunker {
    pub fn new() -> Chunker {
        Chunker {
            last_encoded_sequence_number: 10,
            last_decoded_sequence_number: 0,
        }
    }

    fn chunk_message_type(message: &SupportedMessage) -> ChunkMessageType {
        match *message {
            SupportedMessage::OpenSecureChannelRequest(_) | SupportedMessage::OpenSecureChannelResponse(_) => ChunkMessageType::OpenSecureChannel,
            SupportedMessage::CloseSecureChannelRequest(_) | SupportedMessage::CloseSecureChannelResponse(_) => ChunkMessageType::CloseSecureChannel,
            _ => ChunkMessageType::Message
        }
    }

    pub fn encode(&mut self, request_id: UInt32, secure_channel_info: &SecureChannelInfo, supported_message: &SupportedMessage) -> std::result::Result<Vec<Chunk>, &'static StatusCode> {
        // TODO multiple chunks

        // External values
        let sequence_number = self.last_encoded_sequence_number + 1;
        self.last_encoded_sequence_number = sequence_number;
        let secure_channel_id = secure_channel_info.secure_channel_id;

        debug!("Creating a chunk for secure channel id {}, sequence id {}", secure_channel_id, sequence_number);

        let message_type = Chunker::chunk_message_type(supported_message);

        let is_first_chunk = true;
        let is_last_chunk = true;
        let chunk_type = if is_last_chunk { ChunkType::Final } else { ChunkType::Intermediate };

        // security header depends on message type
        let security_header = if message_type == ChunkMessageType::OpenSecureChannel {
            SecurityHeader::Asymmetric(AsymmetricSecurityHeader::none())
        } else {
            SecurityHeader::Symmetric(SymmetricSecurityHeader {
                token_id: 0,
            })
        };

        let sequence_header = SequenceHeader {
            sequence_number: sequence_number,
            request_id: request_id,
        };

        let node_id = supported_message.node_id();

        // Calculate the chunk body size
        let mut chunk_body_size = 0;
        chunk_body_size += security_header.byte_len();
        chunk_body_size += sequence_header.byte_len();
        if is_first_chunk {
            // Write a node id
            chunk_body_size += node_id.byte_len();
        }
        chunk_body_size += supported_message.byte_len();
        // TODO encrypted message size
        // TODO padding size
        // TODO signature size

        let message_size = (CHUNK_HEADER_SIZE + chunk_body_size) as u32;

        debug!("Creating a chunk with a size of {}", message_size);

        let chunk_header = ChunkHeader {
            message_type: message_type,
            chunk_type: chunk_type,
            message_size: message_size,
            secure_channel_id: secure_channel_id,
            is_valid: true,
        };

        let mut stream = Cursor::new(vec![0u8; chunk_body_size]);

        // write security header
        debug!("Encoding security header");
        security_header.encode(&mut stream);
        // write sequence header
        debug!("Encoding sequence header");
        sequence_header.encode(&mut stream);
        // Write a node id for the first chunk
        if is_first_chunk {
            debug!("Encoding node id");
            node_id.encode(&mut stream);
        } else {
            debug!("Skipping encoding node id");
        }
        // write message
        debug!("Encoding message");
        supported_message.encode(&mut stream);

        // TODO write padding
        // TODO encrypt
        // TODO calculate signature
        // TODO write signature

        // Now the chunk is made and can be added to the result
        let chunk = Chunk {
            chunk_header: chunk_header,
            chunk_body: stream.into_inner(),
        };

        debug!("Returning chunk, body = {:?}", chunk.chunk_body);
        Ok(vec![chunk])
    }

    /// This function extracts the message from one or more chunks. The chunks should have been
    pub fn decode(&mut self, chunks: &Vec<Chunk>, expected_node_id: Option<NodeId>) -> std::result::Result<SupportedMessage, &'static StatusCode> {
        if chunks.len() != 1 {
            // TODO more than one chunk is not supported yet
            error!("Only one chunk is supported");
            return Err(&BAD_UNEXPECTED_ERROR);
        }

        let chunk = &chunks[0];

        let is_server = true; // TODO externalize for client support

        // Note that OpenSecureChannelRequest has no extension object prefix
        let is_first_chunk = true;
        let chunk_info = chunk.chunk_info(is_first_chunk, Option::None)?;
        debug!("Chunker::decode chunk_info = {:?}", chunk_info);

        // Check the sequence id - should be larger than the last one decoded
        if chunk_info.sequence_header.sequence_number <= self.last_decoded_sequence_number {
            return Err(&BAD_SEQUENCE_NUMBER_INVALID);
        }
        self.last_decoded_sequence_number = chunk_info.sequence_header.sequence_number;

        let body_start = chunk_info.body_offset;
        let body_end = body_start + chunk_info.body_length;
        let chunk_body = &chunk.chunk_body[body_start..body_end];
        debug!("chunk_message_body:");
        debug_buffer(chunk_body);

        // First chunk has an extension object prefix.
        //
        // The extension object prefix is just the node id. A point the spec rather unhelpfully doesn't
        // elaborate on. Probably because people enjoy debugging why the stream pos is out by 1 byte
        // for hours.

        debug!("Setting object id");

        let object_id = if let Some(ref node_id) = chunk_info.node_id {
            let valid_node_id = if node_id.namespace != 0 || !node_id.is_numeric() {
                // Must be ns 0 and numeric
                false
            } else if expected_node_id.is_some() {
                expected_node_id.unwrap() == *node_id
            } else {
                true
            };
            if !valid_node_id {
                error!("The node id read from the stream was not accepted in this context {:?}", node_id);
                return Err(&BAD_UNEXPECTED_ERROR);
            }
            let object_id = node_id.as_object_id();
            if object_id.is_err() {
                error!("The node was not an object id");
                return Err(&BAD_UNEXPECTED_ERROR);
            }
            let object_id = object_id.unwrap();
            debug!("Decoded node id / object id of {:?}", object_id);
            object_id
        } else {
            return Err(&BAD_TCP_MESSAGE_TYPE_INVALID);
        };

        // Now the payload. The node id of the prefix allows us to recognize it.

        // TODO when multiple chunks are supported, probably the easiest way is some
        // kind of cursor that sits on top of the message bodies of each, decrypting the msg if
        // necessary
        let mut chunk_body_stream = &mut Cursor::new(chunk_body);

        let decoded_message = SupportedMessage::decode_by_object_id(&mut chunk_body_stream, object_id);
        if decoded_message.is_err() {
            return Err(&BAD_SERVICE_UNSUPPORTED)
        }
        let decoded_message = decoded_message.unwrap();
        if let SupportedMessage::Invalid(_) = decoded_message {
            debug!("Message is unsupported");
            return Err(&BAD_SERVICE_UNSUPPORTED);
        }

        debug!("Returning decoded msg {:#?}", decoded_message);
        return Ok(decoded_message)
    }
}