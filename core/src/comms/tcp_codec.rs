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

use bytes::{Bytes, BytesMut};
use tokio_io::codec::{Encoder, Decoder};

use opcua_types::tcp_types::{HelloMessage, AcknowledgeMessage, ErrorMessage};
use comms::message_chunk::MessageChunkType;

pub enum TcpChunk {
    Hello(HelloMessage),
    Acknowledge(AcknowledgeMessage),
    Error(ErrorMessage),
}

pub struct TcpCodec;

impl Decoder for TcpCodec {
    // TODO this is going to change to be a chunk
    type Item = TcpChunk;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        if buf.len() > 0 {
            let len = buf.len();
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
        buf.reserve(10); //data.len());
        // buf.put(data);
        Ok(())
    }
}