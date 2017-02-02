pub const HELLO_MESSAGE: &'static [u8] = b"HEL";
pub const ACKNOWLEDGE_MESSAGE: &'static [u8] = b"ACK";
pub const ERROR_MESSAGE: &'static [u8] = b"ERR";
pub const CHUNK_MESSAGE: &'static [u8] = b"MSG";
pub const OPEN_SECURE_CHANNEL_MESSAGE: &'static [u8] = b"OPN";
pub const CLOSE_SECURE_CHANNEL_MESSAGE: &'static [u8] = b"CLO";

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