//! Contains the `BinaryEncoder` trait and helpers for reading and writing of scalar values and
//! other primitives.

use std;
use std::fmt::Debug;
use std::io::{Read, Write, Cursor, Result};

use crate::constants;
use byteorder::{ByteOrder, LittleEndian};

use crate::status_codes::StatusCode;

pub type EncodingResult<T> = std::result::Result<T, StatusCode>;

#[derive(Clone, Copy, Debug)]
pub struct DecodingLimits {
    /// Maximum length in bytes (not chars!) of a string. 0 actually means 0, i.e. no string permitted
    pub max_string_length: usize,
    /// Maximum length in bytes of a byte string. 0 actually means 0, i.e. no byte string permitted
    pub max_byte_string_length: usize,
    /// Maximum number of array elements. 0 actually means 0, i.e. no array permitted
    pub max_array_length: usize,
}

impl Default for DecodingLimits {
    fn default() -> Self {
        DecodingLimits {
            max_string_length: constants::MAX_STRING_LENGTH,
            max_byte_string_length: constants::MAX_BYTE_STRING_LENGTH,
            max_array_length: constants::MAX_ARRAY_LENGTH,
        }
    }
}

impl DecodingLimits {
    /// This can be useful for decoding extension objects where the payload is not expected to contain
    /// any string or array.
    pub fn minimal() -> Self {
        DecodingLimits {
            max_string_length: 0,
            max_byte_string_length: 0,
            max_array_length: 0,
        }
    }
}

/// OPC UA Binary Encoding interface. Anything that encodes to binary must implement this. It provides
/// functions to calculate the size in bytes of the struct (for allocating memory), encoding to a stream
/// and decoding from a stream.
pub trait BinaryEncoder<T> {
    /// Returns the exact byte length of the structure as it would be if `encode` were called.
    /// This may be called prior to writing to ensure the correct amount of space is available.
    fn byte_len(&self) -> usize;
    /// Encodes the instance to the write stream.
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize>;
    /// Decodes an instance from the read stream. The decoding limits are restrictions set by the server / client
    /// on the length of strings, arrays etc. If these limits are exceeded the implementation should
    /// return with a `BadDecodingError` as soon as possible.
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<T>;

    // Convenience method for encoding a message straight into an array of bytes. It is preferable to reuse buffers than
    // to call this so it should be reserved for tests and trivial code.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::with_capacity(self.byte_len()));
        let _ = self.encode(&mut buffer);
        buffer.into_inner()
    }
}

/// Converts an IO encoding error (and logs when in error) into an EncodingResult
pub fn process_encode_io_result(result: Result<usize>) -> EncodingResult<usize> {
    result.map_err(|err| {
        trace!("Encoding error - {:?}", err);
        StatusCode::BadEncodingError
    })
}

/// Converts an IO encoding error (and logs when in error) into an EncodingResult
pub fn process_decode_io_result<T>(result: Result<T>) -> EncodingResult<T> where T: Debug {
    result.map_err(|err| {
        trace!("Decoding error - {:?}", err);
        StatusCode::BadDecodingError
    })
}

/// Calculates the length in bytes of an array of encoded type
pub fn byte_len_array<T: BinaryEncoder<T>>(values: &Option<Vec<T>>) -> usize {
    let mut size = 4;
    if let Some(ref values) = values {
        size += values.iter().map(|v| v.byte_len()).sum::<usize>();
    }
    size
}

/// Write an array of the encoded type to stream, preserving distinction between null array and empty array
pub fn write_array<S: Write, T: BinaryEncoder<T>>(stream: &mut S, values: &Option<Vec<T>>) -> EncodingResult<usize> {
    let mut size = 0;
    if let Some(ref values) = values {
        size += write_i32(stream, values.len() as i32)?;
        for value in values.iter() {
            size += value.encode(stream)?;
        }
    } else {
        size += write_i32(stream, -1)?;
    }
    Ok(size)
}

/// Reads an array of the encoded type from a stream, preserving distinction between null array and empty array
pub fn read_array<S: Read, T: BinaryEncoder<T>>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Option<Vec<T>>> {
    let len = read_i32(stream)?;
    if len == -1 {
        Ok(None)
    } else if len < -1 {
        error!("Array length is negative value and invalid");
        Err(StatusCode::BadDecodingError)
    } else if len as usize > decoding_limits.max_array_length {
        error!("Array length {} exceeds decoding limit {}", len, decoding_limits.max_array_length);
        Err(StatusCode::BadDecodingError)
    } else {
        let mut values: Vec<T> = Vec::with_capacity(len as usize);
        for _ in 0..len {
            values.push(T::decode(stream, decoding_limits)?);
        }
        Ok(Some(values))
    }
}

/// Writes an unsigned byte to the stream
pub fn write_u8<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<u8> {
    let buf: [u8; 1] = [value.into()];
    process_encode_io_result(stream.write(&buf))
}

/// Writes a signed 16-bit value to the stream
pub fn write_i16<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<i16> {
    let mut buf = [0u8; 2];
    LittleEndian::write_i16(&mut buf, value.into());
    process_encode_io_result(stream.write(&buf))
}

/// Writes an unsigned 16-bit value to the stream
pub fn write_u16<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<u16> {
    let mut buf = [0u8; 2];
    LittleEndian::write_u16(&mut buf, value.into());
    process_encode_io_result(stream.write(&buf))
}

/// Writes a signed 32-bit value to the stream
pub fn write_i32<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<i32> {
    let mut buf = [0u8; 4];
    LittleEndian::write_i32(&mut buf, value.into());
    process_encode_io_result(stream.write(&buf))
}

/// Writes an unsigned 32-bit value to the stream
pub fn write_u32<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<u32> {
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, value.into());
    process_encode_io_result(stream.write(&buf))
}

/// Writes a signed 64-bit value to the stream
pub fn write_i64<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<i64> {
    let mut buf = [0u8; 8];
    LittleEndian::write_i64(&mut buf, value.into());
    process_encode_io_result(stream.write(&buf))
}

/// Writes an unsigned 64-bit value to the stream
pub fn write_u64<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<u64> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, value.into());
    process_encode_io_result(stream.write(&buf))
}

/// Writes a 32-bit precision value to the stream
pub fn write_f32<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<f32> {
    let mut buf = [0u8; 4];
    LittleEndian::write_f32(&mut buf, value.into());
    process_encode_io_result(stream.write(&buf))
}

/// Writes a 64-bit precision value to the stream
pub fn write_f64<T>(stream: &mut dyn Write, value: T) -> EncodingResult<usize> where T: Into<f64> {
    let mut buf = [0u8; 8];
    LittleEndian::write_f64(&mut buf, value.into());
    process_encode_io_result(stream.write(&buf))
}

/// Reads an array of bytes from the stream
pub fn read_bytes(stream: &mut dyn Read, buf: &mut [u8]) -> EncodingResult<usize> {
    let result = stream.read_exact(buf);
    process_decode_io_result(result)?;
    Ok(buf.len())
}

/// Read an unsigned byte from the stream
pub fn read_u8(stream: &mut dyn Read) -> EncodingResult<u8> {
    let mut buf = [0u8];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(buf[0])
}

/// Read an signed 16-bit value from the stream
pub fn read_i16(stream: &mut dyn Read) -> EncodingResult<i16> {
    let mut buf = [0u8; 2];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_i16(&buf))
}

/// Read an unsigned 16-bit value from the stream
pub fn read_u16(stream: &mut dyn Read) -> EncodingResult<u16> {
    let mut buf = [0u8; 2];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_u16(&buf))
}

/// Read a signed 32-bit value from the stream
pub fn read_i32(stream: &mut dyn Read) -> EncodingResult<i32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_i32(&buf))
}

/// Read an unsigned 32-bit value from the stream
pub fn read_u32(stream: &mut dyn Read) -> EncodingResult<u32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_u32(&buf))
}

/// Read a signed 64-bit value from the stream
pub fn read_i64(stream: &mut dyn Read) -> EncodingResult<i64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_i64(&buf))
}

/// Read an unsigned 64-bit value from the stream
pub fn read_u64(stream: &mut dyn Read) -> EncodingResult<u64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_u64(&buf))
}

/// Read a 32-bit precision value from the stream
pub fn read_f32(stream: &mut dyn Read) -> EncodingResult<f32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_f32(&buf))
}

/// Read a 64-bit precision from the stream
pub fn read_f64(stream: &mut dyn Read) -> EncodingResult<f64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_f64(&buf))
}
