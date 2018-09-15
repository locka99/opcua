//! Contains the implementation of `UAString`.

use std::io::{Read, Write};
use std::fmt;

use encoding::{write_i32, BinaryEncoder, EncodingResult, process_encode_io_result, process_decode_io_result};
use basic_types::Int32;
use constants;
use status_codes::StatusCode::{BadDecodingError, BadEncodingLimitsExceeded};

/// A string containing UTF-8 encoded characters.
///
/// A string can also be a null value, so the string value is optional.
/// When there is no string, the value is treated as null
///
/// To avoid naming conflict hell, the String type is named UAString.
#[derive(Eq, PartialEq, Debug, Clone, Hash, Serialize, Deserialize)]
pub struct UAString {
    pub value: Option<String>,
}

impl fmt::Display for UAString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref value) = self.value {
            write!(f, "{}", value)
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
        // Strings are encoded as UTF8 chars preceded by an Int32 length. A -1 indicates a null string
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
            Ok(UAString::null())
        } else if buf_len < -1 {
            error!("String buf length is a negative number {}", buf_len);
            Err(BadDecodingError)
        } else if buf_len > constants::MAX_STRING_LENGTH as i32 {
            error!("String buf length {} is larger than max string length", buf_len);
            Err(BadEncodingLimitsExceeded)
        } else {
            // Create the actual UTF8 string
            let mut string_buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
            string_buf.resize(buf_len as usize, 0u8);
            process_decode_io_result(stream.read_exact(&mut string_buf))?;
            Ok(UAString {
                value: Some(String::from_utf8(string_buf).unwrap())
            })
        }
    }
}

impl From<UAString> for String {
    fn from(value: UAString) -> Self {
        value.as_ref().to_string()
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

impl Default for UAString {
    fn default() -> Self {
        UAString::null()
    }
}

impl UAString {
    /// Returns true if the string is null or empty, false otherwise
    pub fn is_empty(&self) -> bool {
        if self.value.is_none() { true } else { self.value.as_ref().unwrap().is_empty() }
    }

    /// Returns the length of the string or -1 for null.
    pub fn len(&self) -> isize {
        if self.value.is_none() { -1 } else { self.value.as_ref().unwrap().len() as isize }
    }

    /// Create a null string (not the same as an empty string).
    pub fn null() -> UAString {
        UAString { value: None }
    }

    /// Test if the string is null.
    pub fn is_null(&self) -> bool {
        self.value.is_none()
    }
}

/// An XML element.
pub type XmlElement = UAString;