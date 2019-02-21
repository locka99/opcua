//! Contains the implementation of `ByteString`.

use std::io::{Read, Write};

use base64;

use crate::{
    encoding::{write_i32, BinaryEncoder, EncodingResult, DecodingLimits, process_encode_io_result, process_decode_io_result},
    status_codes::StatusCode
};

/// A sequence of octets.
#[derive(Eq, PartialEq, Debug, Clone, Hash, Serialize, Deserialize)]
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

    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let len = i32::decode(stream, decoding_limits)?;
        // Null string?
        if len == -1 {
            Ok(ByteString::null())
        } else if len < -1 {
            error!("ByteString buf length is a negative number {}", len);
            Err(StatusCode::BadDecodingError)
        } else if len as usize > decoding_limits.max_byte_string_length {
            error!("ByteString length {} exceeds decoding limit {}", len, decoding_limits.max_string_length);
            Err(StatusCode::BadDecodingError)
        } else {
            // Create a buffer filled with zeroes and read the byte string over the top
            let mut buf: Vec<u8> = Vec::with_capacity(len as usize);
            buf.resize(len as usize, 0u8);
            process_decode_io_result(stream.read_exact(&mut buf))?;
            Ok(ByteString {
                value: Some(buf)
            })
        }
    }
}

impl<'a, T> From<&'a T> for ByteString where T: AsRef<[u8]> + ?Sized {
    fn from(value: &'a T) -> Self {
        Self::from(value.as_ref().to_vec())
    }
}

impl From<Vec<u8>> for ByteString {
    fn from(value: Vec<u8>) -> Self {
        // Empty bytes will be treated as Some([])
        ByteString { value: Some(value) }
    }
}

impl Into<String> for ByteString {
    fn into(self) -> String {
        self.as_base64()
    }
}

impl Default for ByteString {
    fn default() -> Self {
        ByteString::null()
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

    /// Creates a byte string from a Base64 encoded string
    pub fn from_base64(data: &str) -> Option<ByteString> {
        if let Ok(bytes) = base64::decode(data) {
            Some(Self::from(bytes))
        } else {
            None
        }
    }

    /// Encodes the bytestring as a Base64 encoded string
    pub fn as_base64(&self) -> String {
        // Base64 encodes the byte string so it can be represented as a string
        if let Some(ref value) = self.value {
            base64::encode(value)
        } else {
            base64::encode("")
        }
    }

    /// Create a byte string with a number of random characters. Can be used to create a nonce or
    /// a similar reason.
    pub fn random(number_of_bytes: usize) -> ByteString {
        use ring::rand::{SystemRandom, SecureRandom};
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; number_of_bytes];
        let _ = rng.fill(&mut bytes);
        ByteString::from(bytes)
    }
}
