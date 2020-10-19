// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, diagnostic_info::DiagnosticInfo, encoding::*, node_ids::ObjectId,
    service_types::impls::MessageInfo, status_codes::StatusCode,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ParsingResult {
    pub status_code: StatusCode,
    pub data_status_codes: Option<Vec<StatusCode>>,
    pub data_diagnostic_infos: Option<Vec<DiagnosticInfo>>,
}

impl MessageInfo for ParsingResult {
    fn object_id(&self) -> ObjectId {
        ObjectId::ParsingResult_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<ParsingResult> for ParsingResult {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.status_code.byte_len();
        size += byte_len_array(&self.data_status_codes);
        size += byte_len_array(&self.data_diagnostic_infos);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.status_code.encode(stream)?;
        size += write_array(stream, &self.data_status_codes)?;
        size += write_array(stream, &self.data_diagnostic_infos)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let status_code = StatusCode::decode(stream, decoding_limits)?;
        let data_status_codes: Option<Vec<StatusCode>> =
            read_array(stream, decoding_limits)?;
        let data_diagnostic_infos: Option<Vec<DiagnosticInfo>> =
            read_array(stream, decoding_limits)?;
        Ok(ParsingResult {
            status_code,
            data_status_codes,
            data_diagnostic_infos,
        })
    }
}
