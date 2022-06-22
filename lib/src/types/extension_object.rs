// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the implementation of `ExtensionObject`.

use std::{
    error::Error,
    fmt,
    io::{Cursor, Read, Write},
};

use super::{
    byte_string::ByteString, encoding::*, node_id::NodeId, node_ids::ObjectId,
    status_codes::StatusCode, string::XmlElement,
};

#[derive(Debug)]
pub struct ExtensionObjectError;

impl fmt::Display for ExtensionObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtensionObjectError")
    }
}

impl Error for ExtensionObjectError {}

/// Enumeration that holds the kinds of encoding that an ExtensionObject data may be encoded with.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum ExtensionObjectEncoding {
    /// For an extension object with nothing encoded with it
    None,
    /// For an extension object with data encoded in a ByteString
    ByteString(ByteString),
    /// For an extension object with data encoded in an XML string
    XmlElement(XmlElement),
}

/// An extension object holds a serialized object identified by its node id.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionObject {
    pub node_id: NodeId,
    pub body: ExtensionObjectEncoding,
}

impl Default for ExtensionObject {
    fn default() -> Self {
        Self::null()
    }
}

impl BinaryEncoder<ExtensionObject> for ExtensionObject {
    fn byte_len(&self) -> usize {
        let mut size = self.node_id.byte_len();
        size += match self.body {
            ExtensionObjectEncoding::None => 1,
            ExtensionObjectEncoding::ByteString(ref value) => {
                // Encoding mask + data
                1 + value.byte_len()
            }
            ExtensionObjectEncoding::XmlElement(ref value) => {
                // Encoding mask + data
                1 + value.byte_len()
            }
        };
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.node_id.encode(stream)?;
        match self.body {
            ExtensionObjectEncoding::None => {
                size += write_u8(stream, 0x0)?;
            }
            ExtensionObjectEncoding::ByteString(ref value) => {
                // Encoding mask + data
                size += write_u8(stream, 0x1)?;
                size += value.encode(stream)?;
            }
            ExtensionObjectEncoding::XmlElement(ref value) => {
                // Encoding mask + data
                size += write_u8(stream, 0x2)?;
                size += value.encode(stream)?;
            }
        }
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        // Extension object is depth checked to prevent deep recursion
        let _depth_lock = decoding_options.depth_lock()?;
        let node_id = NodeId::decode(stream, decoding_options)?;
        let encoding_type = u8::decode(stream, decoding_options)?;
        let body = match encoding_type {
            0x0 => ExtensionObjectEncoding::None,
            0x1 => {
                ExtensionObjectEncoding::ByteString(ByteString::decode(stream, decoding_options)?)
            }
            0x2 => {
                ExtensionObjectEncoding::XmlElement(XmlElement::decode(stream, decoding_options)?)
            }
            _ => {
                error!("Invalid encoding type {} in stream", encoding_type);
                return Err(StatusCode::BadDecodingError);
            }
        };
        Ok(ExtensionObject { node_id, body })
    }
}

impl ExtensionObject {
    /// Creates a null extension object, i.e. one with no value or payload
    pub fn null() -> ExtensionObject {
        ExtensionObject {
            node_id: NodeId::null(),
            body: ExtensionObjectEncoding::None,
        }
    }

    /// Tests for null node id.
    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }

    /// Tests for empty body.
    pub fn is_empty(&self) -> bool {
        self.is_null() || matches!(self.body, ExtensionObjectEncoding::None)
    }

    /// Returns the object id of the thing this extension object contains, assuming the
    /// object id can be recognised from the node id.
    pub fn object_id(&self) -> Result<ObjectId, ExtensionObjectError> {
        self.node_id
            .as_object_id()
            .map_err(|_| ExtensionObjectError)
    }

    /// Creates an extension object with the specified node id and the encodable object as its payload.
    /// The body is set to a byte string containing the encoded struct.
    pub fn from_encodable<N, T>(node_id: N, encodable: &T) -> ExtensionObject
    where
        N: Into<NodeId>,
        T: BinaryEncoder<T>,
    {
        // Serialize to extension object
        let mut stream = Cursor::new(vec![0u8; encodable.byte_len()]);
        let _ = encodable.encode(&mut stream);
        ExtensionObject {
            node_id: node_id.into(),
            body: ExtensionObjectEncoding::ByteString(ByteString::from(stream.into_inner())),
        }
    }

    /// Decodes the inner content of the extension object and returns it. The node id is ignored
    /// for decoding. The caller supplies the binary encoder impl that should be used to extract
    /// the data. Errors result in a decoding error.
    pub fn decode_inner<T>(&self, decoding_options: &DecodingOptions) -> EncodingResult<T>
    where
        T: BinaryEncoder<T>,
    {
        match self.body {
            ExtensionObjectEncoding::ByteString(ref byte_string) => {
                if let Some(ref value) = byte_string.value {
                    // let value = value.clone();
                    let mut stream = Cursor::new(value);
                    T::decode(&mut stream, decoding_options)
                } else {
                    Err(StatusCode::BadDecodingError)
                }
            }
            _ => {
                error!("decode_inner called on an unsupported ExtensionObject type");
                Err(StatusCode::BadDecodingError)
            }
        }
    }
}
