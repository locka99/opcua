use std::io::{Cursor, Write};

use opcua_types::SupportedMessage;
use opcua_types::status_code::StatusCode;
use opcua_types::tcp_types::AcknowledgeMessage;
use opcua_types::{BinaryEncoder, EncodingResult};

use comms::secure_channel::SecureChannel;
use comms::chunker::Chunker;
//use debug::log_buffer;

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
}

impl MessageWriter {
    pub fn new(buffer_size: usize) -> MessageWriter {
        MessageWriter {
            buffer: Cursor::new(vec![0u8; buffer_size]),
            last_request_id: DEFAULT_REQUEST_ID,
            last_sent_sequence_number: DEFAULT_SENT_SEQUENCE_NUMBER,
        }
    }

    pub fn write_ack(&mut self, ack: AcknowledgeMessage) -> EncodingResult<usize> {
        ack.encode(&mut self.buffer)
    }

    /// Encodes the message into a series of chunks, encrypts those chunks and writes the
    /// result into the buffer ready to be sent.
    pub fn write(&mut self, request_id: u32, message: SupportedMessage, secure_channel: &SecureChannel) -> Result<u32, StatusCode> {
        trace!("Writing request to buffer");
        // Turn message to chunk(s)
        // TODO max message size and max chunk size
        let chunks = {
            Chunker::encode(self.last_sent_sequence_number + 1, request_id, 0, 0, secure_channel, &message)?
        };

        // Sequence number monotonically increases per chunk
        self.last_sent_sequence_number += chunks.len() as u32;

        // Send chunks

        // This max chunk size allows the message to be encoded to a chunk with header + encoding
        // which is just slightly larger in size (up to 1024 bytes).
        let max_chunk_size = self.buffer.get_ref().len() + 1024;
        let mut data = vec![0u8; max_chunk_size];

        let decoding_limits = secure_channel.decoding_limits();
        for chunk in chunks {
            trace!("Sending chunk of type {:?}", chunk.message_header(&decoding_limits)?.message_type);
            let size = {
                secure_channel.apply_security(&chunk, &mut data)
            };
            match size {
                Ok(size) => {
                    let bytes_written_result = self.buffer.write(&data[..size]);
                    if let Err(error) = bytes_written_result {
                        error!("Error while writing bytes to stream, connection broken, check error {:?}", error);
                        break;
                    }
                }
                Err(err) => {
                    panic!("Applying security to chunk failed - {:?}", err);
                }
            }
        }
        trace!("Message written");
        Ok(request_id)
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