// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the implementation of `DiagnosticInfo`.

use std::io::{Read, Write};

use crate::types::{encoding::*, status_codes::StatusCode, string::UAString};

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
        /// ServiceLevel / SymbolicId
        const SERVICE_LEVEL_SYMBOLIC_ID = 0x0000_0001;
        /// ServiceLevel / LocalizedText
        const SERVICE_LEVEL_LOCALIZED_TEXT = 0x0000_0002;
        /// ServiceLevel / AdditionalInfo
        const SERVICE_LEVEL_ADDITIONAL_INFO = 0x0000_0004;
        /// ServiceLevel / Inner StatusCode
        const SERVICE_LEVEL_LOCALIZED_INNER_STATUS_CODE = 0x0000_0008;
        /// ServiceLevel / Inner Diagnostics
        const SERVICE_LEVEL_LOCALIZED_INNER_DIAGNOSTICS = 0x0000_0010;
        /// OperationLevel / SymbolicId
        const OPERATIONAL_LEVEL_SYMBOLIC_ID = 0x0000_0020;
        /// OperationLevel / LocalizedText
        const OPERATIONAL_LEVEL_LOCALIZED_TEXT = 0x0000_0040;
        /// OperationLevel / AdditionalInfo
        const OPERATIONAL_LEVEL_ADDITIONAL_INFO = 0x0000_0080;
        /// OperationLevel / Inner StatusCode
        const OPERATIONAL_LEVEL_INNER_STATUS_CODE = 0x0000_0100;
        /// OperationLevel / Inner Diagnostics
        const OPERATIONAL_LEVEL_INNER_DIAGNOSTICS = 0x0000_0200;
    }
}

/// Diagnostic information.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticInfo {
    /// A symbolic name for the status code.
    pub symbolic_id: Option<i32>,
    /// A namespace that qualifies the symbolic id.
    pub namespace_uri: Option<i32>,
    /// The locale used for the localized text.
    pub locale: Option<i32>,
    /// A human readable summary of the status code.
    pub localized_text: Option<i32>,
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

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let encoding_mask =
            DiagnosticInfoMask::from_bits_truncate(u8::decode(stream, decoding_options)?);
        let mut diagnostic_info = DiagnosticInfo::default();

        if encoding_mask.contains(DiagnosticInfoMask::HAS_SYMBOLIC_ID) {
            // Read symbolic id
            diagnostic_info.symbolic_id = Some(i32::decode(stream, decoding_options)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_NAMESPACE) {
            // Read namespace
            diagnostic_info.namespace_uri = Some(i32::decode(stream, decoding_options)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_LOCALE) {
            // Read locale
            diagnostic_info.locale = Some(i32::decode(stream, decoding_options)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_LOCALIZED_TEXT) {
            // Read localized text
            diagnostic_info.localized_text = Some(i32::decode(stream, decoding_options)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_ADDITIONAL_INFO) {
            // Read Additional info
            diagnostic_info.additional_info = Some(UAString::decode(stream, decoding_options)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_INNER_STATUS_CODE) {
            // Read inner status code
            diagnostic_info.inner_status_code = Some(StatusCode::decode(stream, decoding_options)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_INNER_DIAGNOSTIC_INFO) {
            // Read inner diagnostic info
            diagnostic_info.inner_diagnostic_info =
                Some(Box::new(DiagnosticInfo::decode(stream, decoding_options)?));
        }
        Ok(diagnostic_info)
    }
}

impl Default for DiagnosticInfo {
    fn default() -> Self {
        DiagnosticInfo::null()
    }
}

impl DiagnosticInfo {
    pub fn null() -> DiagnosticInfo {
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
