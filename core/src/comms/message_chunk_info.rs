use std;
use std::io::Cursor;

use opcua_types::BinaryEncoder;
use opcua_types::StatusCode;
use opcua_types::StatusCode::*;

use crypto::SecurityPolicy;
use comms::security_header::{SecurityHeader, SequenceHeader};
use comms::message_chunk::{MessageChunk, MessageChunkHeader};
use comms::secure_channel::SecureChannel;
use comms::security_header::{AsymmetricSecurityHeader, SymmetricSecurityHeader};

/// Chunk info provides some basic information gleaned from reading the chunk such as offsets into
/// the chunk and so on. The chunk MUST be decrypted before calling this otherwise the values are 
/// garbage.
#[derive(Debug, Clone, PartialEq)]
pub struct ChunkInfo {
    pub message_header: MessageChunkHeader,
    // Chunks either have an asymmetric or symmetric security header
    pub security_header: SecurityHeader,
    /// Sequence header information
    pub sequence_header: SequenceHeader,
    /// Byte offset to sequence header
    pub security_header_offset: usize,
    /// Byte offset to sequence header
    pub sequence_header_offset: usize,
    /// Byte offset to actual message body
    pub body_offset: usize,
    /// Length of message body
    pub body_length: usize,
}

impl ChunkInfo {
    pub fn new(chunk: &MessageChunk, _: &SecureChannel) -> std::result::Result<ChunkInfo, StatusCode> {
        let mut stream = Cursor::new(&chunk.data);

        let message_header = MessageChunkHeader::decode(&mut stream)?;

        // Read the security header
        let security_header_offset = stream.position() as usize;
        let security_header = if chunk.is_open_secure_channel() {
            let result = AsymmetricSecurityHeader::decode(&mut stream);
            if result.is_err() {
                error!("chunk_info() can't decode asymmetric security_header, {:?}", result.unwrap_err());
                return Err(BAD_COMMUNICATION_ERROR);
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
            let result = SymmetricSecurityHeader::decode(&mut stream);
            if result.is_err() {
                error!("chunk_info() can't decode symmetric security_header, {:?}", result.unwrap_err());
                return Err(BAD_COMMUNICATION_ERROR);
            }
            SecurityHeader::Symmetric(result.unwrap())
        };

        let sequence_header_offset = stream.position() as usize;
        let sequence_header_result = SequenceHeader::decode(&mut stream);
        if sequence_header_result.is_err() {
            error!("Cannot decode sequence header {:?}", sequence_header_result.unwrap_err());
            return Err(BAD_COMMUNICATION_ERROR);
        }
        let sequence_header = sequence_header_result.unwrap();

        // Read Body
        let body_offset = stream.position() as usize;

        // All of what follows is the message body
        let body_length = chunk.data.len() - body_offset;

        let chunk_info = ChunkInfo {
            message_header,
            security_header,
            sequence_header,
            security_header_offset,
            sequence_header_offset,
            body_offset,
            body_length,
        };

        Ok(chunk_info)
    }
}
