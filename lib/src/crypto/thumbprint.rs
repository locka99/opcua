// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Functionality for holding a message digest.
use crate::types::ByteString;

/// The thumbprint holds a 20 byte representation of a certificate that can be used as a hash,
/// handshake comparison, a filename hint or similar purpose where a shortened representation
/// of a cert is required. Thumbprint size is dictated by the OPC UA spec
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Thumbprint {
    /// Thumbprint is relatively small and fixed size, so use array to hold value instead of a vec
    /// just to save heap
    value: [u8; Thumbprint::THUMBPRINT_SIZE],
}

impl Into<ByteString> for Thumbprint {
    fn into(self) -> ByteString {
        ByteString::from(&self.value)
    }
}

impl Thumbprint {
    pub const THUMBPRINT_SIZE: usize = 20;

    /// Constructs a thumbprint from a message digest which is expected to be the proper length
    pub fn new(digest: &[u8]) -> Thumbprint {
        if digest.len() != Thumbprint::THUMBPRINT_SIZE {
            panic!("Thumbprint is the wrong length, {}", digest.len());
        }
        let mut value = [0u8; Thumbprint::THUMBPRINT_SIZE];
        value.clone_from_slice(digest);
        Thumbprint { value }
    }

    pub fn as_byte_string(&self) -> ByteString {
        ByteString::from(&self.value)
    }

    /// Returns the thumbprint as a string using hexadecimal values for each byte
    pub fn as_hex_string(&self) -> String {
        let mut hex_string = String::with_capacity(self.value.len() * 2);
        for b in self.value.iter() {
            hex_string.push_str(&format!("{:02x}", b))
        }
        hex_string
    }

    /// Returns the thumbprint
    pub fn value(&self) -> &[u8] {
        &self.value[..]
    }
}
