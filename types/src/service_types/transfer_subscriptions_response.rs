// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, diagnostic_info::DiagnosticInfo, encoding::*, node_ids::ObjectId,
    response_header::ResponseHeader, service_types::impls::MessageInfo,
    service_types::TransferResult,
};

#[derive(Debug, Clone, PartialEq)]
pub struct TransferSubscriptionsResponse {
    pub response_header: ResponseHeader,
    pub results: Option<Vec<TransferResult>>,
    pub diagnostic_infos: Option<Vec<DiagnosticInfo>>,
}

impl MessageInfo for TransferSubscriptionsResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::TransferSubscriptionsResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<TransferSubscriptionsResponse> for TransferSubscriptionsResponse {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.response_header.byte_len();
        size += byte_len_array(&self.results);
        size += byte_len_array(&self.diagnostic_infos);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.response_header.encode(stream)?;
        size += write_array(stream, &self.results)?;
        size += write_array(stream, &self.diagnostic_infos)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let response_header = ResponseHeader::decode(stream, decoding_limits)?;
        let results: Option<Vec<TransferResult>> = read_array(stream, decoding_limits)?;
        let diagnostic_infos: Option<Vec<DiagnosticInfo>> =
            read_array(stream, decoding_limits)?;
        Ok(TransferSubscriptionsResponse {
            response_header,
            results,
            diagnostic_infos,
        })
    }
}
