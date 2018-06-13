use std;
use std::fmt::Debug;
use std::io::{Read, Write, Result};

use byteorder::{ByteOrder, LittleEndian};

use status_codes::StatusCode;
use status_codes::StatusCode::{BadEncodingError, BadDecodingError};

pub type EncodingResult<T> = std::result::Result<T, StatusCode>;

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

/// Converts an IO encoding error (and logs when in error) into an EncodingResult
pub fn process_encode_io_result(result: Result<usize>) -> EncodingResult<usize> {
    if result.is_err() {
        trace!("Encoding error - {:?}", result.unwrap_err());
        Err(BadEncodingError)
    } else {
        Ok(result.unwrap())
    }
}

/// Converts an IO encoding error (and logs when in error) into an EncodingResult
pub fn process_decode_io_result<T>(result: Result<T>) -> EncodingResult<T> where T: Debug {
    if result.is_err() {
        trace!("Decoding error - {:?}", result.unwrap_err());
        Err(BadDecodingError)
    } else {
        Ok(result.unwrap())
    }
}

/// Calculates the length in bytes of an array of encoded type
pub fn byte_len_array<T: BinaryEncoder<T>>(values: &Option<Vec<T>>) -> usize {
    let mut size = 4;
    if let &Some(ref values) = values {
        size += values.iter().map(|v| v.byte_len()).sum::<usize>();
    }
    size
}

/// Write an array of the encoded type to stream, preserving distinction between null array and empty array
pub fn write_array<S: Write, T: BinaryEncoder<T>>(stream: &mut S, values: &Option<Vec<T>>) -> EncodingResult<usize> {
    let mut size = 0;
    if let &Some(ref values) = values {
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
pub fn read_array<S: Read, T: BinaryEncoder<T>>(stream: &mut S) -> EncodingResult<Option<Vec<T>>> {
    let len = read_i32(stream)?;
    if len == -1 {
        Ok(None)
    } else if len < -1 {
        error!("Array length is negative value and invalid");
        Err(BadDecodingError)
    } else {
        let mut values: Vec<T> = Vec::with_capacity(len as usize);
        for _ in 0..len {
            values.push(T::decode(stream)?);
        }
        Ok(Some(values))
    }
}

/// Writes an unsigned byte to the stream
pub fn write_u8(stream: &mut Write, value: u8) -> EncodingResult<usize> {
    let buf: [u8; 1] = [value];
    process_encode_io_result(stream.write(&buf))
}

/// Writes a signed 16-bit value to the stream
pub fn write_i16(stream: &mut Write, value: i16) -> EncodingResult<usize> {
    let mut buf = [0u8; 2];
    LittleEndian::write_i16(&mut buf, value);
    process_encode_io_result(stream.write(&buf))
}

/// Writes an unsigned 16-bit value to the stream
pub fn write_u16(stream: &mut Write, value: u16) -> EncodingResult<usize> {
    let mut buf = [0u8; 2];
    LittleEndian::write_u16(&mut buf, value);
    process_encode_io_result(stream.write(&buf))
}

/// Writes a signed 32-bit value to the stream
pub fn write_i32(stream: &mut Write, value: i32) -> EncodingResult<usize> {
    let mut buf = [0u8; 4];
    LittleEndian::write_i32(&mut buf, value);
    process_encode_io_result(stream.write(&buf))
}

/// Writes an unsigned 32-bit value to the stream
pub fn write_u32(stream: &mut Write, value: u32) -> EncodingResult<usize> {
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, value);
    process_encode_io_result(stream.write(&buf))
}

/// Writes a signed 64-bit value to the stream
pub fn write_i64(stream: &mut Write, value: i64) -> EncodingResult<usize> {
    let mut buf = [0u8; 8];
    LittleEndian::write_i64(&mut buf, value);
    process_encode_io_result(stream.write(&buf))
}

/// Writes an unsigned 64-bit value to the stream
pub fn write_u64(stream: &mut Write, value: u64) -> EncodingResult<usize> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, value);
    process_encode_io_result(stream.write(&buf))
}

/// Writes a 32-bit precision value to the stream
pub fn write_f32(stream: &mut Write, value: f32) -> EncodingResult<usize> {
    let mut buf = [0u8; 4];
    LittleEndian::write_f32(&mut buf, value);
    process_encode_io_result(stream.write(&buf))
}

/// Writes a 64-bit precision value to the stream
pub fn write_f64(stream: &mut Write, value: f64) -> EncodingResult<usize> {
    let mut buf = [0u8; 8];
    LittleEndian::write_f64(&mut buf, value);
    process_encode_io_result(stream.write(&buf))
}

/// Reads an array of bytes from the stream
pub fn read_bytes(stream: &mut Read, buf: &mut [u8]) -> EncodingResult<usize> {
    let result = stream.read_exact(buf);
    let _ = process_decode_io_result(result)?;
    Ok(buf.len())
}

/// Read an unsigned byte from the stream
pub fn read_u8(stream: &mut Read) -> EncodingResult<u8> {
    let mut buf = [0u8];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(buf[0])
}

/// Read an signed 16-bit value from the stream
pub fn read_i16(stream: &mut Read) -> EncodingResult<i16> {
    let mut buf = [0u8; 2];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(LittleEndian::read_i16(&buf))
}

/// Read an unsigned 16-bit value from the stream
pub fn read_u16(stream: &mut Read) -> EncodingResult<u16> {
    let mut buf = [0u8; 2];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(LittleEndian::read_u16(&buf))
}

/// Read a signed 32-bit value from the stream
pub fn read_i32(stream: &mut Read) -> EncodingResult<i32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(LittleEndian::read_i32(&buf))
}

/// Read an unsigned 32-bit value from the stream
pub fn read_u32(stream: &mut Read) -> EncodingResult<u32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(LittleEndian::read_u32(&buf))
}

/// Read a signed 64-bit value from the stream
pub fn read_i64(stream: &mut Read) -> EncodingResult<i64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(LittleEndian::read_i64(&buf))
}

/// Read an unsigned 64-bit value from the stream
pub fn read_u64(stream: &mut Read) -> EncodingResult<u64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(LittleEndian::read_u64(&buf))
}

/// Read a 32-bit precision value from the stream
pub fn read_f32(stream: &mut Read) -> EncodingResult<f32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(LittleEndian::read_f32(&buf))
}

/// Read a 64-bit precision from the stream
pub fn read_f64(stream: &mut Read) -> EncodingResult<f64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    let _ = process_decode_io_result(result)?;
    Ok(LittleEndian::read_f64(&buf))
}
