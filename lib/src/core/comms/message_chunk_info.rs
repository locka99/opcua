// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::io::Cursor;

use crate::{
    crypto::SecurityPolicy,
    types::{status_code::StatusCode, BinaryEncoder},
};

use super::{
    message_chunk::{MessageChunk, MessageChunkHeader},
    secure_channel::SecureChannel,
    security_header::{
        AsymmetricSecurityHeader, SecurityHeader, SequenceHeader, SymmetricSecurityHeader,
    },
};

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
    pub fn new(
        chunk: &MessageChunk,
        secure_channel: &SecureChannel,
    ) -> std::result::Result<ChunkInfo, StatusCode> {
        let mut stream = Cursor::new(&chunk.data);

        let decoding_options = secure_channel.decoding_options();

        let message_header = MessageChunkHeader::decode(&mut stream, &decoding_options)?;

        // Read the security header
        let security_header_offset = stream.position() as usize;
        let security_header = if chunk.is_open_secure_channel(&decoding_options) {
            let security_header = AsymmetricSecurityHeader::decode(&mut stream, &decoding_options)
                .map_err(|err| {
                    error!(
                        "chunk_info() cannot decode asymmetric security_header, {:?}",
                        err
                    );
                    StatusCode::BadCommunicationError
                })?;

            let security_policy = if security_header.security_policy_uri.is_null() {
                SecurityPolicy::None
            } else {
                SecurityPolicy::from_uri(security_header.security_policy_uri.as_ref())
            };

            if security_policy == SecurityPolicy::Unknown {
                error!(
                    "Security policy of chunk is unsupported, policy = {:?}",
                    security_header.security_policy_uri
                );
                return Err(StatusCode::BadSecurityPolicyRejected);
            }

            // Anything related to policy can be worked out here
            SecurityHeader::Asymmetric(security_header)
        } else {
            let security_header = SymmetricSecurityHeader::decode(&mut stream, &decoding_options)
                .map_err(|err| {
                error!(
                    "chunk_info() cannot decode symmetric security_header, {:?}",
                    err
                );
                StatusCode::BadCommunicationError
            })?;
            SecurityHeader::Symmetric(security_header)
        };

        let sequence_header_offset = stream.position() as usize;
        let sequence_header =
            SequenceHeader::decode(&mut stream, &decoding_options).map_err(|err| {
                error!("Cannot decode sequence header {:?}", err);
                StatusCode::BadCommunicationError
            })?;

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
