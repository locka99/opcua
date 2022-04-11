// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the definition of `QualifiedName`.
use std::io::{Read, Write};

use crate::types::{encoding::*, string::*};

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

impl<'a> From<&'a str> for QualifiedName {
    fn from(value: &'a str) -> Self {
        Self {
            namespace_index: 0,
            name: UAString::from(value),
        }
    }
}

impl From<&String> for QualifiedName {
    fn from(value: &String) -> Self {
        Self {
            namespace_index: 0,
            name: UAString::from(value),
        }
    }
}

impl From<String> for QualifiedName {
    fn from(value: String) -> Self {
        Self {
            namespace_index: 0,
            name: UAString::from(value),
        }
    }
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

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let namespace_index = u16::decode(stream, decoding_options)?;
        let name = UAString::decode(stream, decoding_options)?;
        Ok(QualifiedName {
            namespace_index,
            name,
        })
    }
}

impl QualifiedName {
    pub fn new<T>(namespace_index: u16, name: T) -> QualifiedName
    where
        T: Into<UAString>,
    {
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
