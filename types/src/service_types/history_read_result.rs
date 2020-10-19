// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, byte_string::ByteString, encoding::*,
    extension_object::ExtensionObject, node_ids::ObjectId,
    service_types::impls::MessageInfo, status_codes::StatusCode,
};

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryReadResult {
    pub status_code: StatusCode,
    pub continuation_point: ByteString,
    pub history_data: ExtensionObject,
}

impl MessageInfo for HistoryReadResult {
    fn object_id(&self) -> ObjectId {
        ObjectId::HistoryReadResult_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<HistoryReadResult> for HistoryReadResult {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.status_code.byte_len();
        size += self.continuation_point.byte_len();
        size += self.history_data.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.status_code.encode(stream)?;
        size += self.continuation_point.encode(stream)?;
        size += self.history_data.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let status_code = StatusCode::decode(stream, decoding_limits)?;
        let continuation_point = ByteString::decode(stream, decoding_limits)?;
        let history_data = ExtensionObject::decode(stream, decoding_limits)?;
        Ok(HistoryReadResult {
            status_code,
            continuation_point,
            history_data,
        })
    }
}
