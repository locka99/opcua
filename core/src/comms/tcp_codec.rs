//! The codec is an implementation of a tokio Encoder/Decoder which can be used to read
//! data from the socket in terms of frames which in our case are any of the following:
//!
//! * HEL - Hello message
//! * ACK - Acknowledge message
//! * ERR - Error message
//! * MSG - Message chunk
//! * OPN - Open Secure Channel message
//! * CLO - Close Secure Channel message
use std::io;

use bytes::{Bytes, BytesMut, IntoBuf};
use tokio_io::codec::{Encoder, Decoder};

use opcua_types::tcp_types::{MessageHeader, HelloMessage, AcknowledgeMessage, ErrorMessage, MESSAGE_HEADER_LEN};
use opcua_types::encoding::BinaryEncoder;
use opcua_types::status_code::StatusCode;
use comms::message_chunk::{MessageChunkHeader, MessageChunk};

// TODO this is going to replace message_reader and message_writer

pub enum TcpChunk {
    Hello(HelloMessage),
    Acknowledge(AcknowledgeMessage),
    Error(ErrorMessage),
    Chunk(MessageChunkHeader, MessageChunk),
}

pub struct TcpCodec;

impl Decoder for TcpCodec {
    type Item = TcpChunk;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() > MESSAGE_HEADER_LEN {
            /* let mut buf = buf.into_buf();

            let message_header = {
                MessageHeader::decode(&mut buf).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
            };

            */

            /*
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
                MessageType::Chunk => Message::MessageChunk(MessageChunk::decode(&mut message_stream)?),
                _ => { return Err(BadCommunicationError); }
            };
            messages.push(message);
            */

            Ok(None) // Some(buf.split_to(len)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for TcpCodec {
    type Item = TcpChunk;
    type Error = io::Error;

    fn encode(&mut self, data: Self::Item, buf: &mut BytesMut) -> Result<(), io::Error> {
        match data {
            TcpChunk::Hello(msg) => {
                buf.reserve(msg.byte_len());
                // buf.put(msg);
                // buf.put(data);
            }
            TcpChunk::Acknowledge(msg) => {
                buf.reserve(msg.byte_len());
                // buf.put(data);
            }
            TcpChunk::Error(msg) => {
                buf.reserve(msg.byte_len());
                // buf.put(data);
            }
            TcpChunk::Chunk(header, msg) => {
                buf.reserve(msg.byte_len());
                // buf.put(data);
            }
        }
        Ok(())
    }
}