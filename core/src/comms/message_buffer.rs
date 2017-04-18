use std;
use std::io::{Cursor};

use debug::*;
use types::*;
use comms::*;

#[derive(Debug)]
pub enum Message {
    Hello(HelloMessage),
    Acknowledge(AcknowledgeMessage),
    Error(ErrorMessage),
    Chunk(Chunk)
}

/// The message buffer stores bytes read from the input and speculatively turns them into messages.
pub struct MessageBuffer {
    in_buffer: Vec<u8>,
}

impl MessageBuffer {
    pub fn new(incoming_buffer_size: usize) -> MessageBuffer {
        MessageBuffer {
            in_buffer: Vec::with_capacity(incoming_buffer_size),
        }
    }

    /// Store bytes and analyse them for chunks. If chunks are pending, the result is true
    pub fn store_bytes(&mut self, bytes: &[u8]) -> std::result::Result<Vec<Message>, StatusCode> {
        debug_buffer("Received bytes:", bytes);

        self.in_buffer.extend(bytes.iter().cloned());

        // Now analyse buffer to see if it contains chunks
        let mut messages = Vec::new();
        while self.in_buffer.len() > MESSAGE_HEADER_LEN {
            let incoming_buffer_len = self.in_buffer.len();
            let message_header = {
                let mut in_stream = Cursor::new(&self.in_buffer);
                MessageHeader::decode(&mut in_stream)?
            };

            // Test if message bytes are there yet
            let message_size = message_header.message_size as usize;
            if incoming_buffer_len < message_size {
                break;
            }

            let message_buffer: Vec<u8> = self.in_buffer.drain(0..message_size).collect();
            let mut message_stream = Cursor::new(&message_buffer);

            let message = match message_header.message_type {
                MessageType::Acknowledge => Message::Acknowledge(AcknowledgeMessage::decode(&mut message_stream)?),
                MessageType::Hello => Message::Hello(HelloMessage::decode(&mut message_stream)?),
                MessageType::Error => Message::Error(ErrorMessage::decode(&mut message_stream)?),
                MessageType::Chunk => Message::Chunk(Chunk::decode(&mut message_stream)?),
                _ => { return Err(BAD_COMMUNICATION_ERROR); }
            };
            messages.push(message);
        }

        Ok(messages)
    }
}