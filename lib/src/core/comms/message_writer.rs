// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::io::{Cursor, Write};

use crate::types::{status_code::StatusCode, BinaryEncoder, EncodingResult};

use super::{chunker::Chunker, secure_channel::SecureChannel, tcp_types::AcknowledgeMessage};

use crate::core::supported_message::SupportedMessage;

const DEFAULT_REQUEST_ID: u32 = 1000;
const DEFAULT_SENT_SEQUENCE_NUMBER: u32 = 0;

/// SocketWriter is a wrapper around the writable half of a tokio stream and a buffer which
/// will be dumped into that stream.
pub struct MessageWriter {
    /// The send buffer
    buffer: Cursor<Vec<u8>>,
    /// The last request id
    last_request_id: u32,
    /// Last sent sequence number
    last_sent_sequence_number: u32,
    /// Maximum size of a message, total. Use 0 for no limit
    max_message_size: usize,
    /// Maximum size of a chunk. Use 0 for no limit
    max_chunk_count: usize,
}

impl MessageWriter {
    pub fn new(
        buffer_size: usize,
        max_message_size: usize,
        max_chunk_count: usize,
    ) -> MessageWriter {
        MessageWriter {
            buffer: Cursor::new(vec![0u8; buffer_size]),
            last_request_id: DEFAULT_REQUEST_ID,
            last_sent_sequence_number: DEFAULT_SENT_SEQUENCE_NUMBER,
            max_message_size,
            max_chunk_count,
        }
    }

    pub fn write_ack(&mut self, ack: &AcknowledgeMessage) -> EncodingResult<usize> {
        ack.encode(&mut self.buffer)
    }

    /// Encodes the message into a series of chunks, encrypts those chunks and writes the
    /// result into the buffer ready to be sent.
    pub fn write(
        &mut self,
        request_id: u32,
        message: SupportedMessage,
        secure_channel: &SecureChannel,
    ) -> Result<u32, StatusCode> {
        trace!("Writing request to buffer");
        // Turn message to chunk(s)
        let chunks = Chunker::encode(
            self.last_sent_sequence_number + 1,
            request_id,
            self.max_message_size,
            0,
            secure_channel,
            &message,
        )?;

        if self.max_chunk_count > 0 && chunks.len() > self.max_chunk_count {
            error!(
                "Cannot write message since {} chunks exceeds {} chunk limit",
                chunks.len(),
                self.max_chunk_count
            );
            Err(StatusCode::BadCommunicationError)
        } else {
            // Sequence number monotonically increases per chunk
            self.last_sent_sequence_number += chunks.len() as u32;

            // Send chunks

            // This max chunk size allows the message to be encoded to a chunk with header + encoding
            // which is just slightly larger in size (up to 1024 bytes).
            let data_buffer_size = self.buffer.get_ref().len() + 1024;
            let mut data = vec![0u8; data_buffer_size];
            for chunk in chunks {
                trace!("Sending chunk {:?}", chunk);
                let size = secure_channel.apply_security(&chunk, &mut data)?;
                self.buffer.write(&data[..size]).map_err(|error| {
                    error!(
                        "Error while writing bytes to stream, connection broken, check error {:?}",
                        error
                    );
                    StatusCode::BadCommunicationError
                })?;
            }
            trace!("Message written");
            Ok(request_id)
        }
    }

    pub fn next_request_id(&mut self) -> u32 {
        self.last_request_id += 1;
        self.last_request_id
    }

    /// Clears the buffer
    fn clear(&mut self) {
        self.buffer.set_position(0);
    }

    /// Yields any results to write, resetting the buffer back afterwards
    pub fn bytes_to_write(&mut self) -> Vec<u8> {
        let pos = self.buffer.position() as usize;
        let result = (self.buffer.get_ref())[0..pos].to_vec();
        // Buffer MUST be cleared here, otherwise races are possible
        self.clear();
        result
    }
}
