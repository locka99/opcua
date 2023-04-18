// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the definition of `QualifiedName`.
use std::io::{Read, Write};

use crate::types::{encoding::*, string::*};

/// An identifier for a error or condition that is associated with a value or an operation.
///
/// A name qualified by a namespace.
/// 
/// For JSON, the namespace_index is saved as "Uri" and MUST be a numeric value or it will not parse. This is
/// is in accordance with OPC UA spec that says to save the index as a numeric according to rules cut and
/// pasted from spec below:
///
/// Name   The Name component of the QualifiedName.
///
/// Uri    The _NamespaceIndexcomponent_ of the QualifiedNameencoded as a JSON number. The Urifield
///        is omitted if the NamespaceIndex equals 0. For the non-reversible form, the
///        NamespaceUriassociated with the NamespaceIndexportion of the QualifiedNameis encoded as
///        JSON string unless the NamespaceIndexis 1 or if NamespaceUriis unknown. In these cases,
///        the NamespaceIndexis encoded as a JSON number.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct QualifiedName {
    /// The namespace index
    #[serde(rename = "Uri")]
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
