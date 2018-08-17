use std;
use std::io::{Cursor, Write};

use tokio::net::TcpStream;
use tokio_io::io::WriteHalf;

use opcua_types::{BinaryEncoder, SupportedMessage, UInt32};
use opcua_types::status_codes::StatusCode;

use comms::secure_channel::SecureChannel;
use comms::chunker::Chunker;
use comms::handshake::{HelloMessage, ErrorMessage};
//use debug::log_buffer;

const DEFAULT_REQUEST_ID: UInt32 = 1000;
const DEFAULT_SENT_SEQUENCE_NUMBER: UInt32 = 0;

/// SocketWriter is a wrapper around the writable half of a tokio stream and a buffer which
/// will be dumped into that stream.
pub struct MessageWriter {
    /// Writing portion of socket
    pub write_half: WriteHalf<TcpStream>,
    /// The send buffer
    pub buffer: Cursor<Vec<u8>>,
    /// The last request id
    last_request_id: UInt32,
    /// Last sent sequence number
    last_sent_sequence_number: UInt32,
}

impl MessageWriter {
    pub fn new(write_half: WriteHalf<TcpStream>, buffer_size: usize) -> MessageWriter {
        MessageWriter {
            write_half,
            buffer: Cursor::new(vec![0u8; buffer_size]),
            last_request_id: DEFAULT_REQUEST_ID,
            last_sent_sequence_number: DEFAULT_SENT_SEQUENCE_NUMBER,
        }
    }

    /// Encodes the message into a series of chunks, encrypts those chunks and writes the
    /// result into the buffer ready to be sent.
    pub fn write(&mut self, message: SupportedMessage, secure_channel: &mut SecureChannel) -> Result<UInt32, StatusCode> {
        let request_id = self.next_request_id();

        trace!("Writing request to buffer");
        // Turn message to chunk(s)
        // TODO max message size and max chunk size
        let chunks = {
            Chunker::encode(self.last_sent_sequence_number + 1, request_id, 0, 0, secure_channel, &message)?
        };

        // Sequence number monotonically increases per chunk
        self.last_sent_sequence_number += chunks.len() as UInt32;

        // Send chunks
        let max_chunk_size = 32768; // FIXME TODO
        let mut data = vec![0u8; max_chunk_size + 1024];
        for chunk in chunks {
            trace!("Sending chunk of type {:?}", chunk.message_header()?.message_type);
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

    fn next_request_id(&mut self) -> UInt32 {
        self.last_request_id += 1;
        self.last_request_id
    }

    pub fn clear(&mut self) {
        self.buffer.set_position(0);
    }

    pub fn write_half(&mut self) -> &mut WriteHalf<TcpStream> {
        &mut self.write_half
    }

    pub fn write_hello(&mut self, endpoint_url: &str, send_buffer_size: usize, receive_buffer_size: usize, max_message_size: usize) {
        let msg = HelloMessage::new(endpoint_url,
                          send_buffer_size,
                          receive_buffer_size,
                          max_message_size);
        debug!("Writing HEL {:?}", msg);
        let _ = msg.encode(&mut self.buffer);
    }

    pub fn write_error(&mut self, status_code: StatusCode) {
        let msg = ErrorMessage::from_status_code(status_code);
        debug!("Writing ERR {:?}", msg);
        let _ = msg.encode(&mut self.buffer);
    }

    pub fn flush(&mut self) -> std::io::Result<usize> {
        if self.buffer.position() == 0 {
            Ok(0)
        } else {
            let result = {
                let out_buf_stream = &self.buffer;
                let bytes_to_write = out_buf_stream.position() as usize;
                let buffer_slice = &out_buf_stream.get_ref()[0..bytes_to_write];
                trace!("Writing {} bytes to socket", buffer_slice.len());
                // log_buffer("Writing bytes to client:", buffer_slice);
                let result = self.write_half.write(&buffer_slice);
                let _ = self.write_half.flush();

                match result {
                    Err(err) => {
                        error!("Error writing bytes - {:?}", err);
                        Err(err)
                    }
                    Ok(bytes_written) => {
                        if bytes_to_write != bytes_written {
                            error!("Error writing bytes - bytes_to_write = {}, bytes_written = {}", bytes_to_write, bytes_written);
                        } else {
                            trace!("Bytes written = {}", bytes_written);
                        }
                        Ok(bytes_written)
                    }
                }
            };
            // Clear the buffer
            self.clear();
            result
        }
    }
}