// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{
    self,
    io::{Read, Write},
};

use crate::types::{
    data_types::*, date_time::DateTime, diagnostic_info::DiagnosticInfo, encoding::*,
    extension_object::ExtensionObject, request_header::RequestHeader, status_codes::StatusCode,
    string::UAString,
};

/// The `ResponseHeader` contains information common to every response from server to client.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseHeader {
    pub timestamp: UtcTime,
    pub request_handle: IntegerId,
    pub service_result: StatusCode,
    pub service_diagnostics: DiagnosticInfo,
    pub string_table: Option<Vec<UAString>>,
    pub additional_header: ExtensionObject,
}

impl BinaryEncoder<ResponseHeader> for ResponseHeader {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.timestamp.byte_len();
        size += self.request_handle.byte_len();
        size += self.service_result.byte_len();
        size += self.service_diagnostics.byte_len();
        size += byte_len_array(&self.string_table);
        size += self.additional_header.byte_len();
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.timestamp.encode(stream)?;
        size += self.request_handle.encode(stream)?;
        size += self.service_result.encode(stream)?;
        size += self.service_diagnostics.encode(stream)?;
        size += write_array(stream, &self.string_table)?;
        size += self.additional_header.encode(stream)?;
        assert_eq!(size, self.byte_len());
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let timestamp = UtcTime::decode(stream, decoding_options)?;
        let request_handle = IntegerId::decode(stream, decoding_options)?;
        let service_result = StatusCode::decode(stream, decoding_options)?;
        let service_diagnostics = DiagnosticInfo::decode(stream, decoding_options)?;
        let string_table: Option<Vec<UAString>> = read_array(stream, decoding_options)?;
        let additional_header = ExtensionObject::decode(stream, decoding_options)?;
        Ok(ResponseHeader {
            timestamp,
            request_handle,
            service_result,
            service_diagnostics,
            string_table,
            additional_header,
        })
    }
}

impl ResponseHeader {
    pub fn new_good(request_header: &RequestHeader) -> ResponseHeader {
        ResponseHeader::new_service_result(request_header, StatusCode::Good)
    }

    pub fn new_service_result(
        request_header: &RequestHeader,
        service_result: StatusCode,
    ) -> ResponseHeader {
        ResponseHeader::new_timestamped_service_result(
            DateTime::now(),
            request_header,
            service_result,
        )
    }

    pub fn new_timestamped_service_result(
        timestamp: DateTime,
        request_header: &RequestHeader,
        service_result: StatusCode,
    ) -> ResponseHeader {
        ResponseHeader {
            timestamp,
            request_handle: request_header.request_handle,
            service_result,
            service_diagnostics: DiagnosticInfo::default(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        }
    }

    /// For testing, nothing else
    pub fn null() -> ResponseHeader {
        ResponseHeader {
            timestamp: DateTime::now(),
            request_handle: 0,
            service_result: StatusCode::Good,
            service_diagnostics: DiagnosticInfo::default(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        }
    }
}
