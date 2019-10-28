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
use std::sync::{Arc, RwLock};

use bytes::{BytesMut, BufMut};
use tokio_io::codec::{Encoder, Decoder};

use opcua_types::tcp_types::{MessageType, MessageHeader, HelloMessage, AcknowledgeMessage, ErrorMessage, MESSAGE_HEADER_LEN};
use opcua_types::encoding::{BinaryEncoder, DecodingLimits};
use opcua_types::status_code::StatusCode;

use crate::comms::message_chunk::MessageChunk;

#[derive(Debug)]
pub enum Message {
    Hello(HelloMessage),
    Acknowledge(AcknowledgeMessage),
    Error(ErrorMessage),
    Chunk(MessageChunk),
}

/// Implements a tokio codec that as close as possible, allows incoming data to be transformed into
/// OPC UA message chunks with no intermediate buffers. Chunks are subsequently transformed into
/// messages so there is still some buffers within message chunks, but not at the raw socket level.
pub struct TcpCodec {
    decoding_limits: DecodingLimits,
    abort: Arc<RwLock<bool>>,
}

impl Decoder for TcpCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.is_abort() {
            // Abort immediately
            debug!("TcpCodec decode abort flag has been set and is terminating");
            Err(io::Error::from(StatusCode::BadOperationAbandoned))
        } else if buf.len() > MESSAGE_HEADER_LEN {

            // Every OPC UA message has at least 8 bytes of header to be read to see what follows

            // Get the message header
            let message_header = {
                let mut buf = io::Cursor::new(&buf[0..MESSAGE_HEADER_LEN]);
                MessageHeader::decode(&mut buf, &self.decoding_limits)?
            };

            // Once we have the header we can infer the message size required to read the rest of
            // the message. The buffer needs to have at least that amount of bytes in it for the
            // whole message to be extracted.
            let message_size = message_header.message_size as usize;
            if buf.len() >= message_size {
                // Extract the message bytes from the buffer & decode them into a message
                let mut buf = buf.split_to(message_size);
                let message = Self::decode_message(message_header, &mut buf, &self.decoding_limits)
                    .map_err(|e| {
                        error!("Codec got an error {:?} while decoding a message", e);
                        io::Error::from(e)
                    })?;
                Ok(Some(message))
            } else {
                // Not enough bytes
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

impl Encoder for TcpCodec {
    type Item = Message;
    type Error = io::Error;

    fn encode(&mut self, data: Self::Item, buf: &mut BytesMut) -> Result<(), io::Error> {
        match data {
            Message::Hello(msg) => self.write(msg, buf),
            Message::Acknowledge(msg) => self.write(msg, buf),
            Message::Error(msg) => self.write(msg, buf),
            Message::Chunk(msg) => self.write(msg, buf),
        }
    }
}

impl TcpCodec {
    /// Constructs a new TcpCodec. The abort flag is set to terminate the codec even while it is
    /// waiting for a frame to arrive.
    pub fn new(abort: Arc<RwLock<bool>>, decoding_limits: DecodingLimits) -> TcpCodec {
        TcpCodec {
            abort,
            decoding_limits,
        }
    }

    // Writes the encodable thing into the buffer.
    fn write<T>(&self, msg: T, buf: &mut BytesMut) -> Result<(), io::Error> where T: BinaryEncoder<T> + std::fmt::Debug {
        buf.reserve(msg.byte_len());
        msg.encode(&mut buf.writer())
            .map(|_| ())
            .map_err(|err| {
                error!("Error writing message {:?}, err = {}", msg, err);
                io::Error::new(io::ErrorKind::Other, format!("Error = {}", err))
            })
    }

    fn is_abort(&self) -> bool {
        let abort = self.abort.read().unwrap();
        *abort
    }

    /// Reads a message out of the buffer, which is assumed by now to be the proper length
    fn decode_message(message_header: MessageHeader, buf: &mut BytesMut, decoding_limits: &DecodingLimits) -> Result<Message, StatusCode> {
        let mut buf = io::Cursor::new(&buf[..]);
        match message_header.message_type {
            MessageType::Acknowledge => {
                Ok(Message::Acknowledge(AcknowledgeMessage::decode(&mut buf, decoding_limits)?))
            }
            MessageType::Hello => {
                Ok(Message::Hello(HelloMessage::decode(&mut buf, decoding_limits)?))
            }
            MessageType::Error => {
                Ok(Message::Error(ErrorMessage::decode(&mut buf, decoding_limits)?))
            }
            MessageType::Chunk => {
                Ok(Message::Chunk(MessageChunk::decode(&mut buf, decoding_limits)?))
            }
            MessageType::Invalid => {
                error!("Message type for chunk is invalid.");
                Err(StatusCode::BadCommunicationError)
            }
        }
    }
}
