use std;
use std::io::Cursor;

use opcua_types::*;

use comms::{MessageIsFinalType, SecureChannel, MessageChunk, MessageChunkType};
use crypto::SecurityPolicy;

/// The Chunker is responsible for turning messages to chunks and chunks into messages.
pub struct Chunker {}

impl Chunker {
    /// Tests what kind of chunk type is used for the supported message.
    fn message_type(message: &SupportedMessage) -> MessageChunkType {
        match *message {
            SupportedMessage::OpenSecureChannelRequest(_) | SupportedMessage::OpenSecureChannelResponse(_) => MessageChunkType::OpenSecureChannel,
            SupportedMessage::CloseSecureChannelRequest(_) | SupportedMessage::CloseSecureChannelResponse(_) => MessageChunkType::CloseSecureChannel,
            _ => MessageChunkType::Message
        }
    }

    /// Ensure all of the supplied chunks have sequence numbers greater than the input sequence number and the preceding chunk
    ///
    /// The function returns the last sequence number in the series for success, or
    /// BAD_SEQUENCE_NUMBER_INVALID for failure.
    pub fn validate_chunk_sequences(starting_sequence_number: UInt32, secure_channel: &SecureChannel, chunks: &Vec<MessageChunk>) -> Result<UInt32, StatusCode> {
        let first_sequence_number = {
            let chunk_info = chunks[0].chunk_info(secure_channel)?;
            chunk_info.sequence_header.sequence_number
        };
        if first_sequence_number < starting_sequence_number {
            error!("First sequence number of {} is less than last value {}", first_sequence_number, starting_sequence_number);
            return Err(BAD_SEQUENCE_NUMBER_INVALID);
        }
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_info = chunk.chunk_info(secure_channel)?;
            let sequence_number = chunk_info.sequence_header.sequence_number;
            let expected_sequence_number = first_sequence_number + i as UInt32;
            // Check the sequence id - should be larger than the last one decoded
            if sequence_number != expected_sequence_number {
                error!("Chunk sequence number of {} is not the expected value of {}, idx {}", sequence_number, expected_sequence_number, i);
                return Err(BAD_SEQUENCE_NUMBER_INVALID);
            }
        }
        Ok(first_sequence_number + chunks.len() as UInt32 - 1)
    }

    /// Encodes a message using the supplied sequence number and secure channel info and emits the corresponding chunks
    ///
    /// max_chunk_size refers to the maximum byte length that a chunk should not exceed or 0 for no limit
    /// max_message_size refers to the maximum byte length of a message or 0 for no limit
    ///
    pub fn encode(sequence_number: UInt32, request_id: UInt32, max_message_size: usize, max_chunk_size: usize, secure_channel: &SecureChannel, supported_message: &SupportedMessage) -> std::result::Result<Vec<MessageChunk>, StatusCode> {
        let security_policy = secure_channel.security_policy;
        if security_policy == SecurityPolicy::Unknown {
            panic!("Security policy cannot be unknown");
        }

        // Client / server stacks should validate the length of a message before sending it and
        // here makes as good a place as any to do that.
        let mut message_size = supported_message.byte_len();
        if max_message_size > 0 && message_size > max_message_size {
            warn!("Max message size is {} and message {} exceeds that", max_message_size, message_size);
            // TODO Client stack should report a BAD_REQUEST_TOO_LARGE 
            return Err(BAD_RESPONSE_TOO_LARGE);
        }

        let node_id = supported_message.node_id();
        message_size += node_id.byte_len();

        let message_type = Chunker::message_type(supported_message);
        let mut stream = Cursor::new(vec![0u8; message_size]);

        debug!("Encoding node id {:?}", node_id);
        let _ = node_id.encode(&mut stream);
        let _ = supported_message.encode(&mut stream)?;
        let data = stream.into_inner();

        let result = if max_chunk_size > 0 {
            let max_body_per_chunk = MessageChunk::body_size_from_message_size(message_type, secure_channel, max_chunk_size);
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
                let chunk = MessageChunk::new(sequence_number + i as u32, request_id, message_type, is_final, secure_channel, data_chunk, max_chunk_size)?;
                chunks.push(chunk);
            }
            chunks
        } else {
            let chunk = MessageChunk::new(sequence_number, request_id, message_type, MessageIsFinalType::Final, secure_channel, &data, 0)?;
            vec![chunk]
        };
        Ok(result)
    }

    /// Decodes a series of chunks to create a message. The message must be of a `SupportedMessage`
    /// type otherwise an error will occur.
    pub fn decode(chunks: &Vec<MessageChunk>, secure_channel: &SecureChannel, expected_node_id: Option<NodeId>) -> std::result::Result<SupportedMessage, StatusCode> {
        // TODO all chunks should be verified first

        // Validate the data and calculate the size first
        let mut data_size: usize = 0;
        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_info = chunk.chunk_info(secure_channel)?;
            debug!("Chunker::decode chunk_info = {:?}", chunk_info);
            // The last most chunk is expected to be final, the rest intermediate
            let expected_is_final = if i == chunks.len() - 1 {
                MessageIsFinalType::Final
            } else {
                MessageIsFinalType::Intermediate
            };
            if chunk_info.message_header.is_final != expected_is_final {
                return Err(BAD_DECODING_ERROR);
            }
            // TODO sequence numbers expected to be consecutive
            // TODO request number should be the same
            let body_start = chunk_info.body_offset;
            let body_end = body_start + chunk_info.body_length;
            data_size += chunk.data[body_start..body_end].len();
        }

        // Read the data into a contiguous buffer. The assumption is the data is encrypted / verified by now
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

        // Read node id from stream
        let node_id = NodeId::decode(&mut data)?;
        let object_id = {
            let valid_node_id = if node_id.namespace != 0 || !node_id.is_numeric() {
                // Must be ns 0 and numeric
                error!("Expecting chunk to contain a OPC UA request or response");
                false
            } else if let Some(expected_node_id) = expected_node_id {
                let matches_expected = expected_node_id == node_id;
                if !matches_expected {
                    error!("Chunk node id {:?} does not match expected {:?}", node_id, expected_node_id);
                }
                matches_expected
            } else {
                true
            };
            if !valid_node_id {
                error!("The node id read from the stream was not accepted in this context {:?}", node_id);
                return Err(BAD_UNEXPECTED_ERROR);
            }
            let object_id = node_id.as_object_id();
            if object_id.is_err() {
                error!("The node {:?} was not an object id", node_id);
                return Err(BAD_UNEXPECTED_ERROR);
            }
            let object_id = object_id.unwrap();
            debug!("Decoded node id / object id of {:?}", object_id);
            object_id
        };

        // Now decode the payload using the node id.
        let decoded_message = SupportedMessage::decode_by_object_id(&mut data, object_id);
        if decoded_message.is_err() {
            debug!("Can't decode message {:?}", object_id);
            return Err(BAD_SERVICE_UNSUPPORTED);
        }
        let decoded_message = decoded_message.unwrap();
        if let SupportedMessage::Invalid(_) = decoded_message {
            debug!("Message {:?} is unsupported", object_id);
            return Err(BAD_SERVICE_UNSUPPORTED);
        }

        // debug!("Returning decoded msg {:?}", decoded_message);
        return Ok(decoded_message);
    }
}