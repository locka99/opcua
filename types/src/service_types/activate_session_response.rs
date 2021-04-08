// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]
#![rustfmt::skip]

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    encoding::*,
    basic_types::*,
    service_types::impls::MessageInfo,
    node_ids::ObjectId,
    response_header::ResponseHeader,
    byte_string::ByteString,
    status_codes::StatusCode,
    diagnostic_info::DiagnosticInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ActivateSessionResponse {
    pub response_header: ResponseHeader,
    pub server_nonce: ByteString,
    pub results: Option<Vec<StatusCode>>,
    pub diagnostic_infos: Option<Vec<DiagnosticInfo>>,
}

impl MessageInfo for ActivateSessionResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::ActivateSessionResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<ActivateSessionResponse> for ActivateSessionResponse {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.response_header.byte_len();
        size += self.server_nonce.byte_len();
        size += byte_len_array(&self.results);
        size += byte_len_array(&self.diagnostic_infos);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.response_header.encode(stream)?;
        size += self.server_nonce.encode(stream)?;
        size += write_array(stream, &self.results)?;
        size += write_array(stream, &self.diagnostic_infos)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let response_header = ResponseHeader::decode(stream, decoding_options)?;
        let server_nonce = ByteString::decode(stream, decoding_options)?;
        let results: Option<Vec<StatusCode>> = read_array(stream, decoding_options)?;
        let diagnostic_infos: Option<Vec<DiagnosticInfo>> = read_array(stream, decoding_options)?;
        Ok(ActivateSessionResponse {
            response_header,
            server_nonce,
            results,
            diagnostic_infos,
        })
    }
}
