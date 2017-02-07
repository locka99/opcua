//! The comms module contains all code related to sending / receiving messages from a transport
//! and turning those messages into and out of chunks.

pub const HELLO_MESSAGE: &'static [u8] = b"HEL";
pub const ACKNOWLEDGE_MESSAGE: &'static [u8] = b"ACK";
pub const ERROR_MESSAGE: &'static [u8] = b"ERR";
pub const CHUNK_MESSAGE: &'static [u8] = b"MSG";
pub const OPEN_SECURE_CHANNEL_MESSAGE: &'static [u8] = b"OPN";
pub const CLOSE_SECURE_CHANNEL_MESSAGE: &'static [u8] = b"CLO";

pub const CHUNK_FINAL: u8 = b'F';
pub const CHUNK_INTERMEDIATE: u8 = b'C';
pub const CHUNK_FINAL_ERROR: u8 = b'A';

mod security_policy;
mod chunk;
mod chunker;
mod message_buffer;
mod handshake;
mod supported_message;

pub use self::security_policy::*;
pub use self::chunk::*;
pub use self::chunker::*;
pub use self::message_buffer::*;
pub use self::supported_message::*;
pub use self::handshake::*;