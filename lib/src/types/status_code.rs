// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the hand implemented part of the StatusCode type. The other file, `status_codes.rs` contains
//! the machine generated part.

use std::{
    error::Error,
    fmt,
    fmt::Formatter,
    io::{self, Read, Write},
};

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

pub use crate::types::{encoding::*, status_codes::StatusCode};

// The bitflags! macro implements Debug for StatusCode but it fouls the display because status
// codes are a combination of bits and unique values.

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Displays the StatusCode as it's name, or its name+bitflags
        let bits = self.bitflags();
        if bits.is_empty() {
            write!(f, "{}", self.name())
        } else {
            write!(f, "{}+{:?}", self.name(), bits)
        }
    }
}

impl BinaryEncoder<StatusCode> for StatusCode {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u32(stream, self.bits())
    }

    fn decode<S: Read>(stream: &mut S, _: &DecodingOptions) -> EncodingResult<Self> {
        Ok(StatusCode::from_bits_truncate(read_u32(stream)?))
    }
}

impl Error for StatusCode {}

impl StatusCode {
    /// Returns the bit flags of the status code, i.e. it masks out the actual status code value
    pub fn bitflags(&self) -> StatusCode {
        *self & StatusCode::BIT_MASK
    }

    /// Returns the status only, i.e. it masks out any bit flags that come with the status code
    pub fn status(&self) -> StatusCode {
        *self & StatusCode::STATUS_MASK
    }

    /// Tests if the status code is bad
    pub fn is_bad(&self) -> bool {
        self.contains(StatusCode::IS_ERROR)
    }

    /// Tests if the status code is uncertain
    pub fn is_uncertain(&self) -> bool {
        self.contains(StatusCode::IS_UNCERTAIN)
    }

    /// Tests if the status code is good (i.e. not bad or uncertain)
    pub fn is_good(&self) -> bool {
        !self.is_bad() && !self.is_uncertain()
    }
}

// It would be very nice to be able to override the default implementation in bitflags! macro
// of this fmt::Debug because it breaks on StatusCode
/*
impl fmt::Debug for StatusCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Displays the StatusCode as it's name, or its name+bitflags
        let bits = self.bitflags();
        if bits.is_empty() {
            write!(f, "{}", self.name())
        } else {
            write!(f, "{}+{:?}", self.name(), bits)
        }
    }
}
*/

// Serialize / Deserialize are manually implemented because bitflags! doesn't do it.

impl From<StatusCode> for io::Error {
    fn from(e: StatusCode) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("StatusCode {}", e))
    }
}

impl Serialize for StatusCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

struct StatusCodeVisitor;

impl<'de> Visitor<'de> for StatusCodeVisitor {
    type Value = u32;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unsigned 32-bit integer")
    }

    fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for StatusCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(StatusCode::from_bits_truncate(
            deserializer.deserialize_u32(StatusCodeVisitor)?,
        ))
    }
}

#[test]
fn status_code() {
    assert!(StatusCode::Good.is_good());
    assert!(!StatusCode::Good.is_bad());
    assert!(!StatusCode::Good.is_uncertain());

    assert!(StatusCode::UncertainLastUsableValue.is_uncertain());
    assert!(!StatusCode::UncertainLastUsableValue.is_bad());
    assert!(!StatusCode::UncertainLastUsableValue.is_good());

    assert!(StatusCode::BadDecodingError.is_bad());
    assert!(!StatusCode::BadDecodingError.is_uncertain());
    assert!(!StatusCode::BadDecodingError.is_good());

    assert_eq!(
        (StatusCode::BadDecodingError | StatusCode::HISTORICAL_CALCULATED).status(),
        StatusCode::BadDecodingError
    );
    assert_eq!(
        (StatusCode::BadDecodingError | StatusCode::HISTORICAL_CALCULATED).bitflags(),
        StatusCode::HISTORICAL_CALCULATED
    );
}
