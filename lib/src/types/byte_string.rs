// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `ByteString`.

use std::{
    convert::TryFrom,
    fmt,
    io::{Read, Write},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::types::{
    encoding::{
        process_decode_io_result, process_encode_io_result, write_i32, BinaryEncoder,
        DecodingOptions, EncodingResult,
    },
    status_codes::StatusCode,
    Guid,
};

/// A sequence of octets.
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct ByteString {
    pub value: Option<Vec<u8>>,
}

impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        if self.value.is_none() {
            &[]
        } else {
            self.value.as_ref().unwrap()
        }
    }
}

impl Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.value.is_some() {
            serializer.serialize_str(&self.as_base64())
        } else {
            serializer.serialize_none()
        }
    }
}
struct ByteStringVisitor;

impl<'de> serde::de::Visitor<'de> for ByteStringVisitor {
    type Value = ByteString;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a base64 encoded string value or null")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Self::Value::null())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(self)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::Value::from_base64(v)
            .ok_or_else(|| de::Error::custom("Cannot decode base64 bytestring"))
    }
}

impl<'de> Deserialize<'de> for ByteString {
    fn deserialize<D>(deserializer: D) -> Result<ByteString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_option(ByteStringVisitor)
    }
}

impl BinaryEncoder<ByteString> for ByteString {
    fn byte_len(&self) -> usize {
        // Length plus the actual length of bytes (if not null)
        4 + if self.value.is_none() {
            0
        } else {
            self.value.as_ref().unwrap().len()
        }
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

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let len = i32::decode(stream, decoding_options)?;
        // Null string?
        if len == -1 {
            Ok(ByteString::null())
        } else if len < -1 {
            error!("ByteString buf length is a negative number {}", len);
            Err(StatusCode::BadDecodingError)
        } else if len as usize > decoding_options.max_byte_string_length {
            error!(
                "ByteString length {} exceeds decoding limit {}",
                len, decoding_options.max_byte_string_length
            );
            Err(StatusCode::BadDecodingError)
        } else {
            // Create a buffer filled with zeroes and read the byte string over the top
            let mut buf: Vec<u8> = vec![0u8; len as usize];
            process_decode_io_result(stream.read_exact(&mut buf))?;
            Ok(ByteString { value: Some(buf) })
        }
    }
}

impl<'a, T> From<&'a T> for ByteString
where
    T: AsRef<[u8]> + ?Sized,
{
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

impl From<Guid> for ByteString {
    fn from(value: Guid) -> Self {
        ByteString::from(value.as_bytes().to_vec())
    }
}

impl TryFrom<&ByteString> for Guid {
    type Error = ();

    fn try_from(value: &ByteString) -> Result<Self, Self::Error> {
        if value.is_null_or_empty() {
            Err(())
        } else {
            let bytes = value.as_ref();
            if bytes.len() != 16 {
                Err(())
            } else {
                let mut guid = [0u8; 16];
                guid.copy_from_slice(bytes);
                Ok(Guid::from_bytes(guid))
            }
        }
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

    // Test if the bytestring has an empty value (not the same as null)
    pub fn is_empty(&self) -> bool {
        if let Some(v) = &self.value {
            v.is_empty()
        } else {
            false
        }
    }

    /// Test if the string is null or empty
    pub fn is_null_or_empty(&self) -> bool {
        self.is_null() || self.is_empty()
    }

    /// Creates a byte string from a Base64 encoded string
    pub fn from_base64(data: &str) -> Option<ByteString> {
        if let Ok(bytes) = STANDARD.decode(data) {
            Some(Self::from(bytes))
        } else {
            None
        }
    }

    /// Encodes the bytestring as a Base64 encoded string
    pub fn as_base64(&self) -> String {
        // Base64 encodes the byte string so it can be represented as a string
        if let Some(ref value) = self.value {
            STANDARD.encode(value)
        } else {
            STANDARD.encode("")
        }
    }

    /// This function is meant for use with NumericRange. It creates a substring from this string
    /// from min up to and inclusive of max. Note that min must have an index within the string
    /// but max is allowed to be beyond the end in which case the remainder of the string is
    /// returned (see docs for NumericRange).
    pub fn substring(&self, min: usize, max: usize) -> Result<ByteString, ()> {
        if let Some(ref v) = self.value {
            if min >= v.len() {
                Err(())
            } else {
                let max = if max >= v.len() { v.len() - 1 } else { max };
                let v = v[min..=max].to_vec();
                Ok(ByteString::from(v))
            }
        } else {
            Err(())
        }
    }
}

#[test]
fn bytestring_null() {
    let v = ByteString::null();
    assert!(v.is_null());
}

#[test]
fn bytestring_empty() {
    let v = ByteString::from(&[]);
    assert!(!v.is_null());
    assert!(v.is_null_or_empty());
    assert!(v.is_empty());
}

#[test]
fn bytestring_bytes() {
    let a = [0x1u8, 0x2u8, 0x3u8, 0x4u8];
    let v = ByteString::from(&a);
    assert!(!v.is_null());
    assert!(!v.is_empty());
    assert_eq!(v.value.as_ref().unwrap(), &a);
}

#[test]
fn bytestring_substring() {
    let a = [0x1u8, 0x2u8, 0x3u8, 0x4u8];
    let v = ByteString::from(&a);
    let v2 = v.substring(2, 10000).unwrap();
    let a2 = v2.value.as_ref().unwrap().as_slice();
    assert_eq!(a2, &a[2..]);

    let v2 = v.substring(2, 2).unwrap();
    let a2 = v2.value.as_ref().unwrap().as_slice();
    assert_eq!(a2, &a[2..3]);

    let v2 = v.substring(0, 2000).unwrap();
    assert_eq!(v, v2);
    assert_eq!(v2.value.as_ref().unwrap(), &a);

    assert!(v.substring(4, 10000).is_err());
    assert!(ByteString::null().substring(0, 0).is_err());
}
