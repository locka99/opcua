use std::io::{Read, Write};
use std::fmt;

use encoding::{write_i32, BinaryEncoder, EncodingResult, process_encode_io_result, process_decode_io_result};
use basic_types::Int32;
use constants;
use status_codes::StatusCode::{BadDecodingError, BadEncodingLimitsExceeded};

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

/// An XML element.
/// Data type ID 16
pub type XmlElement = UAString;