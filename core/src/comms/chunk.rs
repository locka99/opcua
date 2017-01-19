use std;
use std::io::{Read, Write, Result, Cursor};

use debug::*;
use types::*;

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

    fn decode<S: Read>(_: &mut S) -> Result<Self> {
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
        size += self.sequence_number.encode(stream)?;
        size += self.request_id.encode(stream)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> Result<Self> {
        let sequence_number = UInt32::decode(stream)?;
        let request_id = UInt32::decode(stream)?;
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

        let _ = self.chunk_header.encode(stream);
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

    pub fn chunk_info(&self, is_first_chunk: bool, _: Option<&mut SecureChannelInfo>) -> std::result::Result<ChunkInfo, &'static StatusCode> {
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
