// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the implementation of `Guid`.

use std::{
    fmt,
    io::{Read, Write},
    str::FromStr,
};

use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::types::encoding::*;

/// A Guid is a 16 byte Globally Unique Identifier.
#[derive(Eq, PartialEq, Clone, Hash)]
pub struct Guid {
    uuid: Uuid,
}

impl Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.uuid.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Guid {
    fn deserialize<D>(deserializer: D) -> Result<Guid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let guid = Guid::from_str(&s).map_err(|_| D::Error::custom("Cannot parse uuid"))?;
        Ok(guid)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.uuid)
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uuid.hyphenated())
    }
}

impl BinaryEncoder<Guid> for Guid {
    fn byte_len(&self) -> usize {
        16
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        size += process_encode_io_result(stream.write(self.uuid.as_bytes()))?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingOptions) -> EncodingResult<Self> {
        let mut bytes = [0u8; 16];
        process_decode_io_result(stream.read_exact(&mut bytes))?;
        Ok(Guid {
            uuid: Uuid::from_bytes(bytes),
        })
    }
}

impl FromStr for Guid {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(|uuid| Guid { uuid }).map_err(|err| {
            error!("Guid cannot be parsed from string, err = {:?}", err);
        })
    }
}

impl From<Uuid> for Guid {
    fn from(uuid: Uuid) -> Self {
        Self { uuid }
    }
}

impl Default for Guid {
    fn default() -> Self {
        Guid::null()
    }
}

impl Guid {
    /// Return a null guid, i.e. 00000000-0000-0000-0000-000000000000
    pub fn null() -> Guid {
        Guid { uuid: Uuid::nil() }
    }

    /// Creates a random Guid
    pub fn new() -> Guid {
        Guid {
            uuid: Uuid::new_v4(),
        }
    }

    /// Returns the bytes of the Guid
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.uuid.as_bytes()
    }

    // Creates a guid from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Guid {
        Guid {
            uuid: Uuid::from_bytes(bytes),
        }
    }
}
