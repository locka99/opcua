// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, byte_string::ByteString, encoding::*, node_ids::ObjectId,
    request_header::RequestHeader, service_types::impls::MessageInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct QueryNextRequest {
    pub request_header: RequestHeader,
    pub release_continuation_point: bool,
    pub continuation_point: ByteString,
}

impl MessageInfo for QueryNextRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::QueryNextRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<QueryNextRequest> for QueryNextRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.request_header.byte_len();
        size += self.release_continuation_point.byte_len();
        size += self.continuation_point.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        size += self.release_continuation_point.encode(stream)?;
        size += self.continuation_point.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let request_header = RequestHeader::decode(stream, decoding_limits)?;
        let release_continuation_point = bool::decode(stream, decoding_limits)?;
        let continuation_point = ByteString::decode(stream, decoding_limits)?;
        Ok(QueryNextRequest {
            request_header,
            release_continuation_point,
            continuation_point,
        })
    }
}
