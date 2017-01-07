use std::io::{Read, Write, Result};

use opcua_core::types::*;

const HELLO_MESSAGE: &'static [u8] = b"HEL";
const ACKNOWLEDGE_MESSAGE: &'static [u8] = b"ACK";
const ERROR_MESSAGE: &'static [u8] = b"ERR";

#[derive(Debug)]
pub struct MessageHeader {
    pub message_type: [u8; 3],
    pub reserved: u8,
    pub message_size: UInt32,
}

impl MessageHeader {
    pub fn new_acknowledge(acknowledge_message: &AcknowledgeMessage) -> MessageHeader {
        MessageHeader {
            message_type: [ACKNOWLEDGE_MESSAGE[0], ACKNOWLEDGE_MESSAGE[1], ACKNOWLEDGE_MESSAGE[2]],
            reserved: b'F',
            message_size: 8 + acknowledge_message.byte_len() as UInt32,
        }
    }

    pub fn new_error(error_message: &ErrorMessage) -> MessageHeader {
        MessageHeader {
            message_type: [ERROR_MESSAGE[0], ERROR_MESSAGE[1], ERROR_MESSAGE[2]],
            reserved: b'F',
            message_size: 8 + error_message.byte_len() as UInt32
        }
    }

    fn is_type(&self, t: &[u8]) -> bool {
        self.message_type == t && self.reserved == b'F'
    }

    pub fn is_hello(&self) -> bool {
        self.is_type(HELLO_MESSAGE)
    }

    pub fn is_acknowledge(&self) -> bool {
        self.is_type(ACKNOWLEDGE_MESSAGE)
    }

    pub fn is_error(&self) -> bool {
        self.is_type(ERROR_MESSAGE)
    }
}

impl BinaryEncoder<MessageHeader> for MessageHeader {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;
        size += stream.write(&self.message_type)?;
        size += write_u8(stream, self.reserved)?;
        size += write_u32(stream, self.message_size)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<MessageHeader> {
        let mut message_type: [u8; 3] = [0, 0, 0];
        stream.read_exact(&mut message_type)?;
        let reserved = read_u8(stream)?;
        let message_size = read_u32(stream)?;
        Ok(MessageHeader {
            message_type: message_type,
            reserved: reserved,
            message_size: message_size,
        })
    }
}

#[derive(Debug)]
pub struct HelloMessage {
    pub protocol_version: UInt32,
    pub receive_buffer_size: UInt32,
    pub send_buffer_size: UInt32,
    pub max_message_size: UInt32,
    pub max_chunk_count: UInt32,
    pub endpoint_url: UAString,
}

impl BinaryEncoder<HelloMessage> for HelloMessage {
    fn byte_len(&self) -> usize {
        20 + self.endpoint_url.byte_len()
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        unimplemented!();
    }

    fn decode(stream: &mut Read) -> Result<HelloMessage> {
        let protocol_version = read_u32(stream)?;
        let receive_buffer_size = read_u32(stream)?;
        let send_buffer_size = read_u32(stream)?;
        let max_message_size = read_u32(stream)?;
        let max_chunk_count = read_u32(stream)?;
        let endpoint_url = UAString::decode(stream)?;
        Ok(HelloMessage {
            protocol_version: protocol_version,
            receive_buffer_size: receive_buffer_size,
            send_buffer_size: send_buffer_size,
            max_message_size: max_message_size,
            max_chunk_count: max_chunk_count,
            endpoint_url: endpoint_url,
        })
    }
}

impl HelloMessage {
    pub fn is_endpoint_url_valid(&self) -> bool {
        if let Some(ref endpoint_url) = self.endpoint_url.value {
            if endpoint_url.len() > 4096 { false } else { true }
        } else {
            true
        }
    }

    pub fn is_valid_buffer_sizes(&self) -> bool {
        const MIN_BUFFER_SIZE: u32 = 8192; // TODO check specs - 8192 or 8196
        self.receive_buffer_size >= MIN_BUFFER_SIZE && self.send_buffer_size >= MIN_BUFFER_SIZE
    }
}

#[derive(Debug)]
pub struct AcknowledgeMessage {
    pub protocol_version: UInt32,
    pub receive_buffer_size: UInt32,
    pub send_buffer_size: UInt32,
    pub max_message_size: UInt32,
    pub max_chunk_count: UInt32,
}

impl BinaryEncoder<AcknowledgeMessage> for AcknowledgeMessage {
    fn byte_len(&self) -> usize {
        20
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;
        size += write_u32(stream, self.protocol_version)?;
        size += write_u32(stream, self.receive_buffer_size)?;
        size += write_u32(stream, self.send_buffer_size)?;
        size += write_u32(stream, self.max_message_size)?;
        size += write_u32(stream, self.max_chunk_count)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<AcknowledgeMessage> {
        unimplemented!();
    }
}

impl AcknowledgeMessage {}

#[derive(Debug)]
pub struct ErrorMessage {
    pub error: UInt32,
    pub reason: UAString,
}

impl BinaryEncoder<ErrorMessage> for ErrorMessage {
    fn byte_len(&self) -> usize {
        4 + self.reason.byte_len()
    }

    fn encode(&self, stream: &mut Write) -> Result<usize> {
        let mut size: usize = 0;
        size += write_u32(stream, self.error)?;
        size += self.reason.encode(stream)?;
        Ok(size)
    }

    fn decode(stream: &mut Read) -> Result<ErrorMessage> {
        unimplemented!();
    }
}

impl ErrorMessage {
    pub fn from_status_code(status_code: &StatusCode) -> ErrorMessage {
        ErrorMessage {
            error: status_code.code,
            reason: UAString::from_str(status_code.description),
        }
    }
}
