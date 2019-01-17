//! Contains definitions of the simple OPC UA scalar types and some others.

use std::{
    fmt,
    io::{Read, Write},
};

use crate::{encoding::*, string::*};

// OPC UA Part 6 - Mappings 1.03 Specification

// Standard UA types onto Rust types:

// Boolean  -> bool
// SByte    -> i8
// Byte     -> u8
// Int16    -> i16
// UInt16   -> u16
// Int32    -> i32
// UInt32   -> u32
// Int64    -> i64
// UInt64   -> u64
// Float    -> f32
// Double   -> f64

impl BinaryEncoder<bool> for bool {
    fn byte_len(&self) -> usize {
        1
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // 0, or 1 for true or false, single byte
        write_u8(stream, if *self { 1 } else { 0 })
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        Ok(read_u8(stream)? == 1)
    }
}

impl BinaryEncoder<i8> for i8 {
    fn byte_len(&self) -> usize {
        1
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u8(stream, *self as u8)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        Ok(read_u8(stream)? as i8)
    }
}

/// An unsigned byt integer value between 0 and 255.
impl BinaryEncoder<u8> for u8 {
    fn byte_len(&self) -> usize {
        1
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u8(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        Ok(read_u8(stream)?)
    }
}

/// A signed integer value between −32768 and 32767.
impl BinaryEncoder<i16> for i16 {
    fn byte_len(&self) -> usize {
        2
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_i16(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        read_i16(stream)
    }
}

/// An unsigned integer value between 0 and 65535.
impl BinaryEncoder<u16> for u16 {
    fn byte_len(&self) -> usize {
        2
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u16(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        read_u16(stream)
    }
}

/// A signed integer value between −2147483648 and 2147483647.
impl BinaryEncoder<i32> for i32 {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_i32(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        read_i32(stream)
    }
}

/// An unsigned integer value between 0 and 4294967295.
impl BinaryEncoder<u32> for u32 {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u32(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        read_u32(stream)
    }
}

/// A signed integer value between −9223372036854775808 and 9223372036854775807.
impl BinaryEncoder<i64> for i64 {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_i64(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        read_i64(stream)
    }
}

/// An unsigned integer value between 0 and 18446744073709551615.
impl BinaryEncoder<u64> for u64 {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u64(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        read_u64(stream)
    }
}

/// An IEEE single precision (32 bit) floating point value.
impl BinaryEncoder<f32> for f32 {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_f32(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        read_f32(stream)
    }
}

/// An IEEE double precision (64 bit) floating point value.
impl BinaryEncoder<f64> for f64 {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_f64(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingLimits) -> EncodingResult<Self> {
        read_f64(stream)
    }
}

// NodeId and ExpandedNodeId are in node_id.rs

/// An identifier for a error or condition that is associated with a value or an operation.
///
/// A name qualified by a namespace.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct QualifiedName {
    /// The namespace index.
    pub namespace_index: u16,
    /// The name.
    pub name: UAString,
}

impl BinaryEncoder<QualifiedName> for QualifiedName {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;
        size += self.namespace_index.byte_len();
        size += self.name.byte_len();
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        size += self.namespace_index.encode(stream)?;
        size += self.name.encode(stream)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let namespace_index = u16::decode(stream, decoding_limits)?;
        let name = UAString::decode(stream, decoding_limits)?;
        Ok(QualifiedName {
            namespace_index,
            name,
        })
    }
}

impl QualifiedName {
    pub fn new<T>(namespace_index: u16, name: T) -> QualifiedName where T: Into<UAString> {
        QualifiedName {
            namespace_index,
            name: name.into(),
        }
    }

    pub fn null() -> QualifiedName {
        QualifiedName {
            namespace_index: 0,
            name: UAString::null(),
        }
    }

    pub fn is_null(&self) -> bool {
        self.namespace_index == 0 && self.name.is_null()
    }
}

/// A human readable text with an optional locale identifier.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct LocalizedText {
    /// The locale. Omitted from stream if null or empty
    pub locale: UAString,
    /// The text in the specified locale. Omitted frmo stream if null or empty.
    pub text: UAString,
}

impl fmt::Display for LocalizedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl BinaryEncoder<LocalizedText> for LocalizedText {
    fn byte_len(&self) -> usize {
        let mut size = 1;
        if !self.locale.is_empty() {
            size += self.locale.byte_len();
        }
        if !self.text.is_empty() {
            size += self.text.byte_len();
        }
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        // A bit mask that indicates which fields are present in the stream.
        // The mask has the following bits:
        // 0x01    Locale
        // 0x02    Text
        let mut encoding_mask: u8 = 0;
        if !self.locale.is_empty() {
            encoding_mask |= 0x1;
        }
        if !self.text.is_empty() {
            encoding_mask |= 0x2;
        }
        size += encoding_mask.encode(stream)?;
        if !self.locale.is_empty() {
            size += self.locale.encode(stream)?;
        }
        if !self.text.is_empty() {
            size += self.text.encode(stream)?;
        }
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let encoding_mask = u8::decode(stream, decoding_limits)?;
        let locale = if encoding_mask & 0x1 != 0 {
            UAString::decode(stream, decoding_limits)?
        } else {
            UAString::null()
        };
        let text = if encoding_mask & 0x2 != 0 {
            UAString::decode(stream, decoding_limits)?
        } else {
            UAString::null()
        };
        Ok(LocalizedText {
            locale,
            text,
        })
    }
}

impl LocalizedText {
    pub fn new(locale: &str, text: &str) -> LocalizedText {
        LocalizedText {
            locale: UAString::from(locale),
            text: UAString::from(text),
        }
    }

    pub fn null() -> LocalizedText {
        LocalizedText {
            locale: UAString::null(),
            text: UAString::null(),
        }
    }
}