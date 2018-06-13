use std::io::{Read, Write};
use std::fmt;

use encoding::*;
use string::*;
use status_codes::StatusCode;

// OPC UA Part 6 - Mappings 1.03 Specification

// These are standard UA types

/// A two-state logical value (true or false).
/// Data type ID 1
pub type Boolean = bool;

impl BinaryEncoder<Boolean> for Boolean {
    fn byte_len(&self) -> usize {
        1
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        // 0, or 1 for true or false, single byte
        write_u8(stream, if *self { 1 } else { 0 })
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let value = if read_u8(stream)? == 1 { true } else { false };
        Ok(value)
    }
}

/// An integer value between −128 and 127.
/// Data type ID 2
pub type SByte = i8;

impl BinaryEncoder<SByte> for SByte {
    fn byte_len(&self) -> usize {
        1
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u8(stream, *self as u8)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        Ok(read_u8(stream)? as i8)
    }
}

/// An integer value between 0 and 255.
/// Data type ID 3
pub type Byte = u8;

impl BinaryEncoder<Byte> for Byte {
    fn byte_len(&self) -> usize {
        1
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u8(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        Ok(read_u8(stream)?)
    }
}

/// An integer value between −32 768 and 32 767.
/// Data type ID 4
pub type Int16 = i16;

impl BinaryEncoder<Int16> for Int16 {
    fn byte_len(&self) -> usize {
        2
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_i16(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        read_i16(stream)
    }
}

/// An integer value between 0 and 65 535.
/// Data type ID 5
pub type UInt16 = u16;

impl BinaryEncoder<UInt16> for UInt16 {
    fn byte_len(&self) -> usize {
        2
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u16(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        read_u16(stream)
    }
}

/// An integer value between −2 147 483 648 and 2 147 483 647.
/// Data type ID 6
pub type Int32 = i32;

impl BinaryEncoder<Int32> for Int32 {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_i32(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        read_i32(stream)
    }
}

/// An integer value between 0 and 4 294 967 295.
/// Data type ID 7
pub type UInt32 = u32;

impl BinaryEncoder<UInt32> for UInt32 {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u32(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        read_u32(stream)
    }
}

/// An integer value between −9 223 372 036 854 775 808 and 9 223 372 036 854 775 807
/// Data type ID 8
pub type Int64 = i64;

impl BinaryEncoder<Int64> for Int64 {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_i64(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        read_i64(stream)
    }
}

/// An integer value between 0 and 18 446 744 073 709 551 615.
/// Data type ID 9
pub type UInt64 = u64;

impl BinaryEncoder<UInt64> for UInt64 {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_u64(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        read_u64(stream)
    }
}

/// An IEEE single precision (32 bit) floating point value.
/// Data type ID 10
pub type Float = f32;

impl BinaryEncoder<Float> for Float {
    fn byte_len(&self) -> usize {
        4
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_f32(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        read_f32(stream)
    }
}

/// An IEEE double precision (64 bit) floating point value.
/// Data type ID 11
pub type Double = f64;

impl BinaryEncoder<Double> for Double {
    fn byte_len(&self) -> usize {
        8
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        write_f64(stream, *self)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        read_f64(stream)
    }
}

// NodeId and ExpandedNodeId are in node_id.rs

/// A numeric identifier for a error or condition that is associated with a value or an operation.
/// Data type ID 19

/// A name qualified by a namespace.
/// Data type ID 20
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct QualifiedName {
    /// The namespace index.
    pub namespace_index: UInt16,
    /// The name.
    pub name: UAString,
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

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let namespace_index = UInt16::decode(stream)?;
        let name = UAString::decode(stream)?;
        Ok(QualifiedName {
            namespace_index,
            name,
        })
    }
}

impl QualifiedName {
    pub fn new(namespace_index: UInt16, name: &str) -> QualifiedName {
        QualifiedName {
            namespace_index,
            name: UAString::from(name),
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

/// Human readable text with an optional locale identifier
/// Data type ID 21
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct LocalizedText {
    /// The locale. Omitted from stream if null or empty
    pub locale: UAString,
    /// The text in the specified locale. Omitted frmo stream if null or empty.
    pub text: UAString,
}

impl fmt::Display for LocalizedText {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl BinaryEncoder<LocalizedText> for LocalizedText {
    fn byte_len(&self) -> usize {
        let mut size = 1;
        if self.locale.len() > 0 {
            size += self.locale.byte_len();
        }
        if self.text.len() > 0 {
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
        let mut encoding_mask: Byte = 0;
        if self.locale.len() > 0 {
            encoding_mask |= 0x1;
        }
        if self.text.len() > 0 {
            encoding_mask |= 0x2;
        }
        size += encoding_mask.encode(stream)?;
        if self.locale.len() > 0 {
            size += self.locale.encode(stream)?;
        }
        if self.text.len() > 0 {
            size += self.text.encode(stream)?;
        }
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let encoding_mask = Byte::decode(stream)?;
        let locale = if encoding_mask & 0x1 != 0 {
            UAString::decode(stream)?
        } else {
            UAString::null()
        };
        let text = if encoding_mask & 0x2 != 0 {
            UAString::decode(stream)?
        } else {
            UAString::null()
        };
        Ok(LocalizedText {
            locale,
            text,
        })
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

// Data type ID 23 is in data_value.rs

// Data type ID 24 is in variant.rs

#[allow(non_snake_case)]
mod DiagnosticInfoMask {
    pub const HAS_SYMBOLIC_ID: u8 = 0x01;
    pub const HAS_NAMESPACE: u8 = 0x02;
    pub const HAS_LOCALIZED_TEXT: u8 = 0x04;
    pub const HAS_LOCALE: u8 = 0x08;
    pub const HAS_ADDITIONAL_INFO: u8 = 0x10;
    pub const HAS_INNER_STATUS_CODE: u8 = 0x20;
    pub const HAS_INNER_DIAGNOSTIC_INFO: u8 = 0x40;
}

#[allow(non_snake_case)]
pub mod DiagnosticFlags {
    pub const SERVICE_LEVEL_SYMBOLIC_ID: u32 = 1;
    pub const SERVICE_LEVEL_LOCALIZED_TEXT: u32 = 1 << 1;
    pub const SERVICE_LEVEL_ADDITIONAL_INFO: u32 = 1 << 2;
    pub const SERVICE_LEVEL_INNER_STATUS_CODE: u32 = 1 << 3;
    pub const SERVICE_LEVEL_INNER_DIAGNOSTICS: u32 = 1 << 4;
    pub const OPERATIONS_LEVEL_SYMBOLIC_ID: u32 = 1 << 5;
    pub const OPERATIONS_LEVEL_LOCALIZED_TEXT: u32 = 1 << 6;
    pub const OPERATIONS_LEVEL_ADDITIONAL_INFO: u32 = 1 << 8;
    pub const OPERATIONS_LEVEL_INNER_STATUS_CODE: u32 = 1 << 9;
    pub const OPERATIONS_LEVEL_INNER_DIAGNOSTICS: u32 = 1 << 10;
}

/// Data type ID 25
#[derive(PartialEq, Debug, Clone)]
pub struct DiagnosticInfo {
    /// A symbolic name for the status code.
    pub symbolic_id: Option<Int32>,
    /// A namespace that qualifies the symbolic id.
    pub namespace_uri: Option<Int32>,
    /// The locale used for the localized text.
    pub locale: Option<Int32>,
    /// A human readable summary of the status code.
    pub localized_text: Option<Int32>,
    /// Detailed application specific diagnostic information.
    pub additional_info: Option<UAString>,

    /// A status code provided by an underlying system.
    pub inner_status_code: Option<StatusCode>,
    /// Diagnostic info associated with the inner status code.
    pub inner_diagnostic_info: Option<Box<DiagnosticInfo>>,
}

impl BinaryEncoder<DiagnosticInfo> for DiagnosticInfo {
    fn byte_len(&self) -> usize {
        let mut size: usize = 0;
        size += 1; // self.encoding_mask())
        if let Some(ref symbolic_id) = self.symbolic_id {
            // Write symbolic id
            size += symbolic_id.byte_len();
        }
        if let Some(ref namespace_uri) = self.namespace_uri {
            // Write namespace
            size += namespace_uri.byte_len()
        }
        if let Some(ref locale) = self.locale {
            // Write locale
            size += locale.byte_len()
        }
        if let Some(ref localized_text) = self.localized_text {
            // Write localized text
            size += localized_text.byte_len()
        }
        if let Some(ref additional_info) = self.additional_info {
            // Write Additional info
            size += additional_info.byte_len()
        }
        if let Some(ref inner_status_code) = self.inner_status_code {
            // Write inner status code
            size += inner_status_code.byte_len()
        }
        if let Some(ref inner_diagnostic_info) = self.inner_diagnostic_info {
            // Write inner diagnostic info
            size += inner_diagnostic_info.byte_len()
        }
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size: usize = 0;
        size += write_u8(stream, self.encoding_mask())?;
        if let Some(ref symbolic_id) = self.symbolic_id {
            // Write symbolic id
            size += write_i32(stream, *symbolic_id)?;
        }
        if let Some(ref namespace_uri) = self.namespace_uri {
            // Write namespace
            size += namespace_uri.encode(stream)?;
        }
        if let Some(ref locale) = self.locale {
            // Write locale
            size += locale.encode(stream)?;
        }
        if let Some(ref localized_text) = self.localized_text {
            // Write localized text
            size += localized_text.encode(stream)?;
        }
        if let Some(ref additional_info) = self.additional_info {
            // Write Additional info
            size += additional_info.encode(stream)?;
        }
        if let Some(ref inner_status_code) = self.inner_status_code {
            // Write inner status code
            size += inner_status_code.encode(stream)?;
        }
        if let Some(ref inner_diagnostic_info) = self.inner_diagnostic_info {
            // Write inner diagnostic info
            size += inner_diagnostic_info.clone().encode(stream)?;
        }
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let encoding_mask = Byte::decode(stream)?;
        let mut diagnostic_info = DiagnosticInfo::new();
        if encoding_mask & DiagnosticInfoMask::HAS_SYMBOLIC_ID != 0 {
            // Read symbolic id
            diagnostic_info.symbolic_id = Some(Int32::decode(stream)?);
        }
        if encoding_mask & DiagnosticInfoMask::HAS_NAMESPACE != 0 {
            // Read namespace
            diagnostic_info.namespace_uri = Some(Int32::decode(stream)?);
        }
        if encoding_mask & DiagnosticInfoMask::HAS_LOCALE != 0 {
            // Read locale
            diagnostic_info.locale = Some(Int32::decode(stream)?);
        }
        if encoding_mask & DiagnosticInfoMask::HAS_LOCALIZED_TEXT != 0 {
            // Read localized text
            diagnostic_info.localized_text = Some(Int32::decode(stream)?);
        }
        if encoding_mask & DiagnosticInfoMask::HAS_ADDITIONAL_INFO != 0 {
            // Read Additional info
            diagnostic_info.additional_info = Some(UAString::decode(stream)?);
        }
        if encoding_mask & DiagnosticInfoMask::HAS_INNER_STATUS_CODE != 0 {
            // Read inner status code
            diagnostic_info.inner_status_code = Some(StatusCode::decode(stream)?);
        }
        if encoding_mask & DiagnosticInfoMask::HAS_INNER_DIAGNOSTIC_INFO != 0 {
            // Read inner diagnostic info
            diagnostic_info.inner_diagnostic_info = Some(Box::new(DiagnosticInfo::decode(stream)?));
        }
        Ok(diagnostic_info)
    }
}

impl DiagnosticInfo {
    pub fn new() -> DiagnosticInfo {
        DiagnosticInfo {
            symbolic_id: None,
            namespace_uri: None,
            locale: None,
            localized_text: None,
            additional_info: None,
            inner_status_code: None,
            inner_diagnostic_info: None,
        }
    }

    pub fn encoding_mask(&self) -> u8 {
        let mut encoding_mask: u8 = 0;
        if self.symbolic_id.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_SYMBOLIC_ID;
        }
        if self.namespace_uri.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_NAMESPACE;
        }
        if self.locale.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_LOCALE;
        }
        if self.localized_text.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_LOCALIZED_TEXT;
        }
        if self.additional_info.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_ADDITIONAL_INFO;
        }
        if self.inner_status_code.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_INNER_STATUS_CODE;
        }
        if self.inner_diagnostic_info.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_INNER_DIAGNOSTIC_INFO;
        }
        encoding_mask
    }
}
