use std::io;
use std::fmt;
use std::fmt::Formatter;

use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{self, Visitor};

pub use crate::status_codes::StatusCode;

// The bitflags! macro implements Debug for StatusCode but it fouls the display because status
// codes are a combination of bits and unique values.

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Displays the StatusCode as it's name, or its name+bitflags
        let bits = *self & StatusCode::BIT_MASK;
        if bits.is_empty() {
            write!(f, "{}", self.name())
        } else {
            write!(f, "{}+{:?}", self.name(), bits)
        }
    }
}

// Serialize / Deserialize are manually implemented because bitflags! doesn't do it.

impl From<StatusCode> for io::Error {
    fn from(e: StatusCode) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("StatusCode {:?}", e))
    }
}

impl Serialize for StatusCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

struct StatusCodeVisitor;

impl<'de> Visitor<'de> for StatusCodeVisitor {
    type Value = u32;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an integer between -2^31 and 2^31")
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
        where D: Deserializer<'de> {
        Ok(StatusCode::from_bits_truncate(deserializer.deserialize_u32(StatusCodeVisitor)?))
    }
}