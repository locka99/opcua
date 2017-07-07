use std;
use std::io::Cursor;

use opcua_types::*;

use comms::{SupportedMessage, ChunkMessageType, SecureChannelToken, Chunk, ChunkType};
use crypto::SecurityPolicy;

/// The Chunker is responsible for turning messages to chunks and chunks into messages.
pub struct Chunker {}

impl Chunker {
    /// Tests what kind of chunk type is used for the supported message.
    fn chunk_message_type(message: &SupportedMessage) -> ChunkMessageType {
        match *message {
            SupportedMessage::OpenSecureChannelRequest(_) | SupportedMessage::OpenSecureChannelResponse(_) => ChunkMessageType::OpenSecureChannel,
            SupportedMessage::CloseSecureChannelRequest(_) | SupportedMessage::CloseSecureChannelResponse(_) => ChunkMessageType::CloseSecureChannel,
            _ => ChunkMessageType::Message
        }
    }

    /// Ensure all of the supplied chunks have sequence numbers greater than the input sequence number and the preceding chunk
    ///
    /// The function returns the last sequence number in the series for success, or
    /// BAD_SEQUENCE_NUMBER_INVALID for failure.
    pub fn validate_chunk_sequences(sequence_number: UInt32, secure_channel_token: &SecureChannelToken, chunks: &Vec<Chunk>) -> Result<UInt32, StatusCode> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        {
            let mut sequence_number = sequence_number;
            for chunk in chunks.iter() {
                let chunk_info = chunk.chunk_info(secure_channel_token)?;
                // Check the sequence id - should be larger than the last one decoded
                //if chunk_info.sequence_header.sequence_number != sequence_number {
                //    error!("Chunk has a sequence number of {} which is less than last decoded sequence number of {}", chunk_info.sequence_header.sequence_number, sequence_number);
                //    return Err(BAD_SEQUENCE_NUMBER_INVALID);
                //}
                sequence_number += 1;
            }
        }
        Ok(sequence_number + chunks.len() as UInt32 - 1)
    }

    /// Encodes a message using the supplied sequence number and secure channel info and emits the corresponding chunks
    ///
    /// max_chunk_size refers to the maximum byte length that a chunk should not exceed or 0 for no limit
    /// max_message_size refers to the maximum byte length of a message or 0 for no limit
    ///
    pub fn encode(sequence_number: UInt32, request_id: UInt32, max_message_size: usize, max_chunk_size: usize, secure_channel_token: &SecureChannelToken, supported_message: &SupportedMessage) -> std::result::Result<Vec<Chunk>, StatusCode> {
        let security_policy = secure_channel_token.security_policy;
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

        let message_type = Chunker::chunk_message_type(supported_message);
        let chunk_type = ChunkType::Final;
        let mut stream = Cursor::new(vec![0u8; message_size]);

        debug!("Encoding node id {:?}", node_id);
        let _ = node_id.encode(&mut stream);
        let _ = supported_message.encode(&mut stream)?;
        let data = stream.into_inner();

        let result = if max_chunk_size > 0 {
            let max_message_per_chunk_size = Chunk::message_size_from_chunk_size(message_type, secure_channel_token, max_chunk_size);
            // Multiple chunks means breaking the data up into sections. Fortunately
            // Rust has a nice function to do just that.
            let data_chunks = data.chunks(max_message_per_chunk_size);
            let mut chunks = Vec::with_capacity(data_chunks.len());
            for (i, data_chunk) in data_chunks.enumerate() {
                let chunk = Chunk::new(sequence_number + i as u32, request_id, message_type, chunk_type, secure_channel_token, data_chunk)?;
                chunks.push(chunk);
            }
            chunks
        } else {
            let chunk = Chunk::new(sequence_number, request_id, message_type, chunk_type, secure_channel_token, &data)?;
            vec![chunk]
        };
        Ok(result)
    }

    /// Decodes a series of chunks to create a message. The message must be of a `SupportedMessage`
    /// type otherwise an error will occur.
    pub fn decode(chunks: &Vec<Chunk>, secure_channel_token: &SecureChannelToken, expected_node_id: Option<NodeId>) -> std::result::Result<SupportedMessage, StatusCode> {
        // TODO all chunks should be verified first

        // Calculate the size of the data
        let mut data_size: usize = 0;
        for chunk in chunks.iter() {
            let chunk_info = chunk.chunk_info(secure_channel_token)?;
            debug!("Chunker::decode chunk_info = {:?}", chunk_info);
            let body_start = chunk_info.body_offset;
            let body_end = body_start + chunk_info.body_length;
            data_size += chunk.chunk_body[body_start..body_end].len();
        }

        // Read the data into a contiguous buffer
        let mut data = Vec::with_capacity(data_size);
        for chunk in chunks.iter() {
            let chunk_info = chunk.chunk_info(secure_channel_token)?;
            let body_start = chunk_info.body_offset;
            let body_end = body_start + chunk_info.body_length;
            let chunk_data = &chunk.chunk_body[body_start..body_end];
            // TODO security policy decrypt
            let decrypted_data = chunk_data;
            data.extend_from_slice(decrypted_data);
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
            return Err(BAD_SERVICE_UNSUPPORTED)
        }
        let decoded_message = decoded_message.unwrap();
        if let SupportedMessage::Invalid(_) = decoded_message {
            debug!("Message {:?} is unsupported", object_id);
            return Err(BAD_SERVICE_UNSUPPORTED);
        }

        // debug!("Returning decoded msg {:?}", decoded_message);
        return Ok(decoded_message)
    }
}