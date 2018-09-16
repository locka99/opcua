//! Contains the implementation of `DiagnosticInfo`.

use std::io::{Read, Write};

use basic_types::*;
use encoding::*;
use status_codes::StatusCode;
use string::UAString;

bitflags! {
    pub struct DiagnosticInfoMask: u8 {
        const HAS_SYMBOLIC_ID = 0x01;
        const HAS_NAMESPACE = 0x02;
        const HAS_LOCALIZED_TEXT = 0x04;
        const HAS_LOCALE = 0x08;
        const HAS_ADDITIONAL_INFO = 0x10;
        const HAS_INNER_STATUS_CODE = 0x20;
        const HAS_INNER_DIAGNOSTIC_INFO = 0x40;
    }
}

bitflags! {
     pub struct DiagnosticBits: u32 {
        /// 0x0000 0001 ServiceLevel / SymbolicId
        const SERVICE_LEVEL_SYMBOLIC_ID = 0x0000_0001;
        /// 0x0000 0002 ServiceLevel / LocalizedText
        const SERVICE_LEVEL_LOCALIZED_TEXT = 0x0000_0002;
        /// 0x0000 0004 ServiceLevel / AdditionalInfo
        const SERVICE_LEVEL_ADDITIONAL_INFO = 0x0000_0004;
        /// 0x0000 0008 ServiceLevel / Inner StatusCode
        const SERVICE_LEVEL_LOCALIZED_INNER_STATUS_CODE = 0x0000_0008;
        /// 0x0000 0010 ServiceLevel / Inner Diagnostics
        const SERVICE_LEVEL_LOCALIZED_INNER_DIAGNOSTICS = 0x0000_0010;
        /// 0x0000 0020 OperationLevel / SymbolicId
        const OPERATIONAL_LEVEL_SYMBOLIC_ID = 0x0000_0020;
        /// 0x0000 0040 OperationLevel / LocalizedText
        const OPERATIONAL_LEVEL_LOCALIZED_TEXT = 0x0000_0040;
        /// 0x0000 0080 OperationLevel / AdditionalInfo
        const OPERATIONAL_LEVEL_ADDITIONAL_INFO = 0x0000_0080;
        /// 0x0000 0100 OperationLevel / Inner StatusCode
        const OPERATIONAL_LEVEL_INNER_STATUS_CODE = 0x0000_0100;
        /// 0x0000 0200 OperationLevel / Inner Diagnostics
        const OPERATIONAL_LEVEL_INNER_DIAGNOSTICS = 0x0000_0200;
    }
}

/// Diagnostic information.
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
        size += write_u8(stream, self.encoding_mask().bits)?;
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
        let encoding_mask = DiagnosticInfoMask::from_bits_truncate(Byte::decode(stream)?);
        let mut diagnostic_info = DiagnosticInfo::default();

        if encoding_mask.contains(DiagnosticInfoMask::HAS_SYMBOLIC_ID) {
            // Read symbolic id
            diagnostic_info.symbolic_id = Some(Int32::decode(stream)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_NAMESPACE) {
            // Read namespace
            diagnostic_info.namespace_uri = Some(Int32::decode(stream)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_LOCALE) {
            // Read locale
            diagnostic_info.locale = Some(Int32::decode(stream)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_LOCALIZED_TEXT) {
            // Read localized text
            diagnostic_info.localized_text = Some(Int32::decode(stream)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_ADDITIONAL_INFO) {
            // Read Additional info
            diagnostic_info.additional_info = Some(UAString::decode(stream)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_INNER_STATUS_CODE) {
            // Read inner status code
            diagnostic_info.inner_status_code = Some(StatusCode::decode(stream)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_INNER_DIAGNOSTIC_INFO) {
            // Read inner diagnostic info
            diagnostic_info.inner_diagnostic_info = Some(Box::new(DiagnosticInfo::decode(stream)?));
        }
        Ok(diagnostic_info)
    }
}

impl Default for DiagnosticInfo {
    fn default() -> Self {
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
}

impl DiagnosticInfo {
    pub fn encoding_mask(&self) -> DiagnosticInfoMask {
        let mut encoding_mask = DiagnosticInfoMask::empty();
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
