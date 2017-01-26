// This types module contains:
// 
// 1. All of the built-in data types described in OPC Part 6 Chapter 5 that are encodable
// 2. All of the standard data types described in OPC Part 3 Chapter 8 (if not covered by 1.)

use std;
use std::io::{Read, Write};

pub type EncodingResult<T> = std::result::Result<T, &'static StatusCode>;

/// OPC UA Binary Encoding interface. Anything that encodes to binary must implement this. It provides
/// functions to calculate the size in bytes of the struct (for allocating memory), encoding to a stream
/// and decoding from a stream.
pub trait BinaryEncoder<T> {
    /// Returns the byte length of the structure. This calculation should be exact and as efficient
    /// as possible.
    fn byte_len(&self) -> usize;
    /// Encodes the instance to the write stream.
    fn encode<S: Write>(&self, _: &mut S) -> EncodingResult<usize>;
    /// Decodes an instance from the read stream.
    fn decode<S: Read>(_: &mut S) -> EncodingResult<T>;
}

mod helpers;
mod encodable_types;
mod data_value;
mod date_time;
mod node_id;
mod variant;
mod data_types;
mod generated;

pub use self::helpers::*;
pub use self::encodable_types::*;
pub use self::data_value::*;
pub use self::date_time::*;
pub use self::node_id::*;
pub use self::variant::*;
pub use self::data_types::*;

pub use self::generated::*;
