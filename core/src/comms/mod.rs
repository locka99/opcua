//! Contains all code related to sending / receiving messages from a transport
//! and turning those messages into and out of chunks.

pub const HELLO_MESSAGE: &'static [u8] = b"HEL";
pub const ACKNOWLEDGE_MESSAGE: &'static [u8] = b"ACK";
pub const ERROR_MESSAGE: &'static [u8] = b"ERR";
pub const CHUNK_MESSAGE: &'static [u8] = b"MSG";
pub const OPEN_SECURE_CHANNEL_MESSAGE: &'static [u8] = b"OPN";
pub const CLOSE_SECURE_CHANNEL_MESSAGE: &'static [u8] = b"CLO";

/// The size of a chunk header, used by several places
pub const MESSAGE_CHUNK_HEADER_SIZE: usize = 12;
pub const SEQUENCE_HEADER_SIZE: usize = 8;

pub const CHUNK_FINAL: u8 = b'F';
pub const CHUNK_INTERMEDIATE: u8 = b'C';
pub const CHUNK_FINAL_ERROR: u8 = b'A';

/// This is a constraint in the existing implementation for the time being.
pub const MAX_CHUNK_COUNT: usize = 1;

/// Minimum size in bytes than any single message chunk can be
pub const MIN_CHUNK_SIZE: usize = 8196;

pub mod chunker;
pub mod handshake;
pub mod message_reader;
pub mod message_chunk;
pub mod message_chunk_info;
pub mod secure_channel;
pub mod security_header;
pub mod message_writer;

pub mod prelude {
    pub use super::MAX_CHUNK_COUNT;
    pub use super::chunker::*;
    pub use super::handshake::*;
    pub use super::message_reader::*;
    pub use super::message_chunk::*;
    pub use super::message_chunk_info::*;
    pub use super::secure_channel::*;
    pub use super::security_header::*;
}
