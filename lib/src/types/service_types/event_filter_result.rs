// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock
//
// This file was autogenerated from Opc.Ua.Types.bsd by tools/schema/gen_types.js
//
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]
#[allow(unused_imports)]
use crate::types::{
    basic_types::*, diagnostic_info::DiagnosticInfo, encoding::*,
    service_types::ContentFilterResult, status_code::StatusCode,
};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq)]
pub struct EventFilterResult {
    pub select_clause_results: Option<Vec<StatusCode>>,
    pub select_clause_diagnostic_infos: Option<Vec<DiagnosticInfo>>,
    pub where_clause_result: ContentFilterResult,
}

impl BinaryEncoder<EventFilterResult> for EventFilterResult {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.select_clause_results);
        size += byte_len_array(&self.select_clause_diagnostic_infos);
        size += self.where_clause_result.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.select_clause_results)?;
        size += write_array(stream, &self.select_clause_diagnostic_infos)?;
        size += self.where_clause_result.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let select_clause_results: Option<Vec<StatusCode>> = read_array(stream, decoding_options)?;
        let select_clause_diagnostic_infos: Option<Vec<DiagnosticInfo>> =
            read_array(stream, decoding_options)?;
        let where_clause_result = ContentFilterResult::decode(stream, decoding_options)?;
        Ok(EventFilterResult {
            select_clause_results,
            select_clause_diagnostic_infos,
            where_clause_result,
        })
    }
}
