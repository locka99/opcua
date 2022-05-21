// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains code for turning messages into chunks and chunks into messages.

use std::io::Cursor;

use crate::{
    core::{
        comms::{
            message_chunk::{MessageChunk, MessageChunkType, MessageIsFinalType},
            secure_channel::SecureChannel,
        },
        supported_message::SupportedMessage,
    },
    crypto::SecurityPolicy,
    types::{
        encoding::BinaryEncoder, node_id::NodeId, node_ids::ObjectId, status_code::StatusCode,
    },
};

/// The Chunker is responsible for turning messages to chunks and chunks into messages.
pub struct Chunker;

impl Chunker {
    /// Tests what kind of chunk type is used for the supported message.
    fn message_type(message: &SupportedMessage) -> MessageChunkType {
        match message {
            SupportedMessage::OpenSecureChannelRequest(_)
            | SupportedMessage::OpenSecureChannelResponse(_) => MessageChunkType::OpenSecureChannel,
            SupportedMessage::CloseSecureChannelRequest(_)
            | SupportedMessage::CloseSecureChannelResponse(_) => {
                MessageChunkType::CloseSecureChannel
            }
            _ => MessageChunkType::Message,
        }
    }

    /// Ensure all of the supplied chunks have a valid secure channel id, and sequence numbers
    /// greater than the input sequence number and the preceding chunk
    ///
    /// The function returns the last sequence number in the series for success, or
    /// `BadSequenceNumberInvalid` or `BadSecureChannelIdInvalid` for failure.
    pub fn validate_chunks(
        starting_sequence_number: u32,
        secure_channel: &SecureChannel,
        chunks: &[MessageChunk],
    ) -> Result<u32, StatusCode> {
        let first_sequence_number = {
            let chunk_info = chunks[0].chunk_info(secure_channel)?;
            chunk_info.sequence_header.sequence_number
        };
        if first_sequence_number < starting_sequence_number {
            error!(
                "First sequence number of {} is less than last value {}",
                first_sequence_number, starting_sequence_number
            );
            Err(StatusCode::BadSequenceNumberInvalid)
        } else {
            let secure_channel_id = secure_channel.secure_channel_id();

            // Validate that all chunks have incrementing sequence numbers and valid chunk types
            let mut expected_request_id: u32 = 0;
            for (i, chunk) in chunks.iter().enumerate() {
                let chunk_info = chunk.chunk_info(secure_channel)?;

                // Check the channel id of each chunk
                if secure_channel_id != 0
                    && chunk_info.message_header.secure_channel_id != secure_channel_id
                {
                    error!(
                        "Secure channel id {} does not match expected id {}",
                        chunk_info.message_header.secure_channel_id, secure_channel_id
                    );
                    return Err(StatusCode::BadSecureChannelIdInvalid);
                }

                // Check the sequence id - should be larger than the last one decoded
                let sequence_number = chunk_info.sequence_header.sequence_number;
                let expected_sequence_number = first_sequence_number + i as u32;
                if sequence_number != expected_sequence_number {
                    error!(
                        "Chunk sequence number of {} is not the expected value of {}, idx {}",
                        sequence_number, expected_sequence_number, i
                    );
                    return Err(StatusCode::BadSecurityChecksFailed);
                }

                // Check the request id against the first chunk's request id
                if i == 0 {
                    expected_request_id = chunk_info.sequence_header.request_id;
                } else if chunk_info.sequence_header.request_id != expected_request_id {
                    error!("Chunk sequence number of {} has a request id {} which is not the expected value of {}, idx {}", sequence_number, chunk_info.sequence_header.request_id, expected_request_id, i);
                    return Err(StatusCode::BadSecurityChecksFailed);
                }
            }
            Ok(first_sequence_number + chunks.len() as u32 - 1)
        }
    }

    /// Encodes a message using the supplied sequence number and secure channel info and emits the corresponding chunks
    ///
    /// max_chunk_count refers to the maximum byte length that a chunk should not exceed or 0 for no limit
    /// max_message_size refers to the maximum byte length of a message or 0 for no limit
    ///
    pub fn encode(
        sequence_number: u32,
        request_id: u32,
        max_message_size: usize,
        max_chunk_size: usize,
        secure_channel: &SecureChannel,
        supported_message: &SupportedMessage,
    ) -> std::result::Result<Vec<MessageChunk>, StatusCode> {
        let security_policy = secure_channel.security_policy();
        if security_policy == SecurityPolicy::Unknown {
            panic!("Security policy cannot be unknown");
        }

        // Client / server stacks should validate the length of a message before sending it and
        // here makes as good a place as any to do that.
        let mut message_size = supported_message.byte_len();
        if max_message_size > 0 && message_size > max_message_size {
            error!(
                "Max message size is {} and message {} exceeds that",
                max_message_size, message_size
            );
            // Client stack should report a BadRequestTooLarge, server BadResponseTooLarge
            Err(if secure_channel.is_client_role() {
                StatusCode::BadRequestTooLarge
            } else {
                StatusCode::BadResponseTooLarge
            })
        } else {
            let node_id = supported_message.node_id();
            message_size += node_id.byte_len();

            let message_type = Chunker::message_type(supported_message);
            let mut stream = Cursor::new(vec![0u8; message_size]);

            trace!("Encoding node id {:?}", node_id);
            let _ = node_id.encode(&mut stream);
            let _ = supported_message.encode(&mut stream)?;
            let data = stream.into_inner();

            let result = if max_chunk_size > 0 {
                let max_body_per_chunk = MessageChunk::body_size_from_message_size(
                    message_type,
                    secure_channel,
                    max_chunk_size,
                )
                .map_err(|_| {
                    error!(
                        "body_size_from_message_size error for max_chunk_size = {}",
                        max_chunk_size
                    );
                    StatusCode::BadTcpInternalError
                })?;

                // Multiple chunks means breaking the data up into sections. Fortunately
                // Rust has a nice function to do just that.
                let data_chunks = data.chunks(max_body_per_chunk);
                let data_chunks_len = data_chunks.len();
                let mut chunks = Vec::with_capacity(data_chunks_len);
                for (i, data_chunk) in data_chunks.enumerate() {
                    let is_final = if i == data_chunks_len - 1 {
                        MessageIsFinalType::Final
                    } else {
                        MessageIsFinalType::Intermediate
                    };
                    let chunk = MessageChunk::new(
                        sequence_number + i as u32,
                        request_id,
                        message_type,
                        is_final,
                        secure_channel,
                        data_chunk,
                    )?;
                    chunks.push(chunk);
                }
                chunks
            } else {
                let chunk = MessageChunk::new(
                    sequence_number,
                    request_id,
                    message_type,
                    MessageIsFinalType::Final,
                    secure_channel,
                    &data,
                )?;
                vec![chunk]
            };
            Ok(result)
        }
    }

    /// Decodes a series of chunks to create a message. The message must be of a `SupportedMessage`
    /// type otherwise an error will occur.
    pub fn decode(
        chunks: &[MessageChunk],
        secure_channel: &SecureChannel,
        expected_node_id: Option<NodeId>,
    ) -> std::result::Result<SupportedMessage, StatusCode> {
        // Calculate the size of data held in all chunks
        let mut data_size: usize = 0;
        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_info = chunk.chunk_info(secure_channel)?;
            // The last most chunk is expected to be final, the rest intermediate
            let expected_is_final = if i == chunks.len() - 1 {
                MessageIsFinalType::Final
            } else {
                MessageIsFinalType::Intermediate
            };
            if chunk_info.message_header.is_final != expected_is_final {
                return Err(StatusCode::BadDecodingError);
            }
            // Calculate how much space data is in the chunk
            let body_start = chunk_info.body_offset;
            let body_end = body_start + chunk_info.body_length;
            data_size += chunk.data[body_start..body_end].len();
        }

        // Read the data into a contiguous buffer. The assumption is the data is decrypted / verified by now
        // TODO this buffer should be externalized so it is not allocated each time
        let mut data = Vec::with_capacity(data_size);
        for chunk in chunks.iter() {
            let chunk_info = chunk.chunk_info(secure_channel)?;

            let body_start = chunk_info.body_offset;
            let body_end = body_start + chunk_info.body_length;
            let body_data = &chunk.data[body_start..body_end];
            data.extend_from_slice(body_data);
        }

        // Make a stream around the data
        let mut data = Cursor::new(data);

        // The extension object prefix is just the node id. A point the spec rather unhelpfully doesn't
        // elaborate on. Probably because people enjoy debugging why the stream pos is out by 1 byte
        // for hours.

        let decoding_options = secure_channel.decoding_options();

        // Read node id from stream
        let node_id = NodeId::decode(&mut data, &decoding_options)?;
        let object_id = Self::object_id_from_node_id(node_id, expected_node_id)?;

        // Now decode the payload using the node id.
        match SupportedMessage::decode_by_object_id(&mut data, object_id, &decoding_options) {
            Ok(decoded_message) => {
                if let SupportedMessage::Invalid(_) = decoded_message {
                    debug!("Message {:?} is unsupported", object_id);
                    Err(StatusCode::BadServiceUnsupported)
                } else {
                    // debug!("Returning decoded msg {:?}", decoded_message);
                    Ok(decoded_message)
                }
            }
            Err(err) => {
                debug!("Cannot decode message {:?}, err = {:?}", object_id, err);
                Err(StatusCode::BadServiceUnsupported)
            }
        }
    }

    fn object_id_from_node_id(
        node_id: NodeId,
        expected_node_id: Option<NodeId>,
    ) -> Result<ObjectId, StatusCode> {
        let valid_node_id = if node_id.namespace != 0 || !node_id.is_numeric() {
            // Must be ns 0 and numeric
            error!("Expecting chunk to contain a OPC UA request or response");
            false
        } else if let Some(expected_node_id) = expected_node_id {
            let matches_expected = expected_node_id == node_id;
            if !matches_expected {
                error!(
                    "Chunk node id {:?} does not match expected {:?}",
                    node_id, expected_node_id
                );
            }
            matches_expected
        } else {
            true
        };
        if !valid_node_id {
            error!(
                "The node id read from the stream was not accepted in this context {:?}",
                node_id
            );
            Err(StatusCode::BadUnexpectedError)
        } else {
            node_id
                .as_object_id()
                .map_err(|_| {
                    error!("The node {:?} was not an object id", node_id);
                    StatusCode::BadUnexpectedError
                })
                .map(|object_id| {
                    trace!("Decoded node id / object id of {:?}", object_id);
                    object_id
                })
        }
    }
}
