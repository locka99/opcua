//! Contains all code related to sending / receiving messages from a transport
//! and turning those messages into and out of chunks.

pub mod chunker;
pub mod message_chunk;
pub mod message_chunk_info;
pub mod secure_channel;
pub mod security_header;
pub mod message_writer;
pub mod tcp_codec;
pub mod wrapped_tcp_stream;

pub mod prelude {
    pub use super::chunker::*;
    pub use super::tcp_codec::*;
    pub use super::message_chunk::*;
    pub use super::secure_channel::*;
    pub use super::security_header::*;
    pub use super::wrapped_tcp_stream::WrappedTcpStream;
}
