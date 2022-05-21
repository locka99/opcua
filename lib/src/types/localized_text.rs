// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the definition of `LocalizedText`.
use std::{
    fmt,
    io::{Read, Write},
};

use crate::types::{encoding::*, string::*};

/// A human readable text with an optional locale identifier.
#[derive(PartialEq, Default, Debug, Clone, Serialize, Deserialize)]
pub struct LocalizedText {
    /// The locale. Omitted from stream if null or empty
    pub locale: UAString,
    /// The text in the specified locale. Omitted frmo stream if null or empty.
    pub text: UAString,
}

impl<'a> From<&'a str> for LocalizedText {
    fn from(value: &'a str) -> Self {
        Self {
            locale: UAString::from(""),
            text: UAString::from(value),
        }
    }
}

impl From<&String> for LocalizedText {
    fn from(value: &String) -> Self {
        Self {
            locale: UAString::from(""),
            text: UAString::from(value),
        }
    }
}

impl From<String> for LocalizedText {
    fn from(value: String) -> Self {
        Self {
            locale: UAString::from(""),
            text: UAString::from(value),
        }
    }
}

impl fmt::Display for LocalizedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl BinaryEncoder<LocalizedText> for LocalizedText {
    fn byte_len(&self) -> usize {
        let mut size = 1;
        if !self.locale.is_empty() {
            size += self.locale.byte_len();
        }
        if !self.text.is_empty() {
            size += self.text.byte_len();
        }
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        // A bit mask that indicates which fields are present in the stream.
        // The mask has the following bits:
        // 0x01    Locale
        // 0x02    Text
        let mut encoding_mask: u8 = 0;
        if !self.locale.is_empty() {
            encoding_mask |= 0x1;
        }
        if !self.text.is_empty() {
            encoding_mask |= 0x2;
        }
        size += encoding_mask.encode(stream)?;
        if !self.locale.is_empty() {
            size += self.locale.encode(stream)?;
        }
        if !self.text.is_empty() {
            size += self.text.encode(stream)?;
        }
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let encoding_mask = u8::decode(stream, decoding_options)?;
        let locale = if encoding_mask & 0x1 != 0 {
            UAString::decode(stream, decoding_options)?
        } else {
            UAString::null()
        };
        let text = if encoding_mask & 0x2 != 0 {
            UAString::decode(stream, decoding_options)?
        } else {
            UAString::null()
        };
        Ok(LocalizedText { locale, text })
    }
}

impl LocalizedText {
    pub fn new(locale: &str, text: &str) -> LocalizedText {
        LocalizedText {
            locale: UAString::from(locale),
            text: UAString::from(text),
        }
    }

    pub fn null() -> LocalizedText {
        LocalizedText {
            locale: UAString::null(),
            text: UAString::null(),
        }
    }
}
