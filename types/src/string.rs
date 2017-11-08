use std::io::{Read, Write};
use std::fmt;

use encoding::{write_i32, BinaryEncoder, EncodingResult, process_encode_io_result, process_decode_io_result};
use basic_types::Int32;
use constants;
use generated::StatusCode::*;


/// A UTF-8 encoded sequence of Unicode characters.
///
/// A string can hold a null value, so the string value is optional.
/// When there is no string, the value is treated as null
///
/// To avoid naming conflict hell, the String type is named UAString.
///
/// Data type ID 12
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct UAString {
    pub value: Option<String>,
}

impl fmt::Display for UAString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.value.is_some() {
            write!(f, "{}", self.value.as_ref().unwrap())
        } else {
            write!(f, "[null]")
        }
    }
}

impl BinaryEncoder<UAString> for UAString {
    fn byte_len(&self) -> usize {
        // Length plus the actual length of bytes (if not null)
        4 + if self.value.is_none() { 0 } else { self.value.as_ref().unwrap().len() }
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // Strings are uncoded as UTF8 chars preceded by an Int32 length. A -1 indicates a null string
        if self.value.is_none() {
            write_i32(stream, -1)
        } else {
            let value = self.value.clone().unwrap();
            let mut size: usize = 0;
            size += write_i32(stream, value.len() as i32)?;
            let buf = value.as_bytes();
            size += process_encode_io_result(stream.write(&buf))?;
            assert_eq!(size, self.byte_len());
            Ok(size)
        }
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let buf_len = Int32::decode(stream)?;
        // Null string?
        if buf_len == -1 {
            return Ok(UAString::null());
        } else if buf_len < -1 {
            error!("String buf length is a negative number {}", buf_len);
            return Err(BAD_DECODING_ERROR);
        } else if buf_len > constants::MAX_STRING_LENGTH as i32 {
            error!("String buf length {} is larger than max string length", buf_len);
            return Err(BAD_ENCODING_LIMITS_EXCEEDED);
        }

        // Create the actual UTF8 string
        let mut string_buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
        string_buf.resize(buf_len as usize, 0u8);
        process_decode_io_result(stream.read_exact(&mut string_buf))?;
        Ok(UAString {
            value: Some(String::from_utf8(string_buf).unwrap())
        })
    }
}

impl AsRef<str> for UAString {
    fn as_ref(&self) -> &str {
        if self.is_null() { "" } else { self.value.as_ref().unwrap() }
    }
}

impl<'a> From<&'a str> for UAString {
    fn from(value: &'a str) -> Self {
        Self::from(value.to_string())
    }
}

impl From<String> for UAString {
    fn from(value: String) -> Self {
        UAString { value: Some(value) }
    }
}

impl UAString {
    /// Returns the length of the string or -1 for null
    pub fn len(&self) -> isize {
        if self.value.is_none() { -1 } else { self.value.as_ref().unwrap().len() as isize }
    }

    /// Create a null string (not the same as an empty string)
    pub fn null() -> UAString {
        UAString { value: None }
    }

    /// Test if the string is null
    pub fn is_null(&self) -> bool {
        self.value.is_none()
    }
}


/// A sequence of octets.
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct ByteString {
    pub value: Option<Vec<u8>>,
}

impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        if self.value.is_none() { &[] } else { self.value.as_ref().unwrap() }
    }
}

impl BinaryEncoder<ByteString> for ByteString {
    fn byte_len(&self) -> usize {
        // Length plus the actual length of bytes (if not null)
        4 + if self.value.is_none() { 0 } else { self.value.as_ref().unwrap().len() }
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // Strings are uncoded as UTF8 chars preceded by an Int32 length. A -1 indicates a null string
        if self.value.is_none() {
            write_i32(stream, -1)
        } else {
            let mut size: usize = 0;
            let value = self.value.as_ref().unwrap();
            size += write_i32(stream, value.len() as i32)?;
            size += process_encode_io_result(stream.write(value))?;
            assert_eq!(size, self.byte_len());
            Ok(size)
        }
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let buf_len = Int32::decode(stream)?;
        // Null string?
        if buf_len == -1 {
            return Ok(ByteString::null());
        } else if buf_len < -1 {
            error!("ByteString buf length is a negative number {}", buf_len);
            return Err(BAD_DECODING_ERROR);
        } else if buf_len > constants::MAX_BYTE_STRING_LENGTH as i32 {
            error!("ByteString buf length {} is longer than max byte string length", buf_len);
            return Err(BAD_ENCODING_LIMITS_EXCEEDED);
        }

        // Create the actual UTF8 string
        let mut string_buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
        string_buf.resize(buf_len as usize, 0u8);
        process_decode_io_result(stream.read_exact(&mut string_buf))?;
        Ok(ByteString {
            value: Some(string_buf)
        })
    }
}

impl<'a, T> From<&'a T> for ByteString where T: AsRef<[u8]> + ? Sized {
    fn from(value: &'a T) -> Self {
        Self::from(value.as_ref().to_vec())
    }
}

impl From<Vec<u8>> for ByteString {
    fn from(value: Vec<u8>) -> Self {
        ByteString { value: Some(value) }
    }
}

impl ByteString {
    /// Create a null string (not the same as an empty string)
    pub fn null() -> ByteString {
        ByteString { value: None }
    }

    /// Test if the string is null
    pub fn is_null(&self) -> bool {
        self.value.is_none()
    }

    /// Test if the string is null or empty
    pub fn is_null_or_empty(&self) -> bool {
        self.value.is_none() || self.value.as_ref().unwrap().is_empty()
    }

    /// Creates a nonce - 32 bytes of random data
    pub fn nonce() -> ByteString {
        Self::random(32)
    }

    /// Create a byte string with a number of random characters. Can be used to create a nonce or
    /// a similar reason.
    pub fn random(number_of_bytes: usize) -> ByteString {
        use rand::{self, Rng};
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; number_of_bytes];
        rng.fill_bytes(&mut bytes);
        ByteString::from(bytes)
    }
}

/// An XML element.
/// Data type ID 16
pub type XmlElement = UAString;