// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    encoding::*,
    basic_types::*,
    service_types::impls::MessageInfo,
    node_ids::ObjectId,
    response_header::ResponseHeader,
    service_types::ApplicationDescription,
};

#[derive(Debug, Clone, PartialEq)]
pub struct FindServersResponse {
    pub response_header: ResponseHeader,
    pub servers: Option<Vec<ApplicationDescription>>,
}

impl MessageInfo for FindServersResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::FindServersResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<FindServersResponse> for FindServersResponse {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.response_header.byte_len();
        size += byte_len_array(&self.servers);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.response_header.encode(stream)?;
        size += write_array(stream, &self.servers)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let response_header = ResponseHeader::decode(stream, decoding_options)?;
        let servers: Option<Vec<ApplicationDescription>> = read_array(stream, decoding_options)?;
        Ok(FindServersResponse {
            response_header,
            servers,
        })
    }
}
