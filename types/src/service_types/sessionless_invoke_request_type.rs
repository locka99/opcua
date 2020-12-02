// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE
#![rustfmt::skip]

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    encoding::*,
    basic_types::*,
    service_types::impls::MessageInfo,
    node_ids::ObjectId,
    string::UAString,
};

#[derive(Debug, Clone, PartialEq)]
pub struct SessionlessInvokeRequestType {
    pub uris_version: Option<Vec<u32>>,
    pub namespace_uris: Option<Vec<UAString>>,
    pub server_uris: Option<Vec<UAString>>,
    pub locale_ids: Option<Vec<UAString>>,
    pub service_id: u32,
}

impl MessageInfo for SessionlessInvokeRequestType {
    fn object_id(&self) -> ObjectId {
        ObjectId::SessionlessInvokeRequestType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<SessionlessInvokeRequestType> for SessionlessInvokeRequestType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.uris_version);
        size += byte_len_array(&self.namespace_uris);
        size += byte_len_array(&self.server_uris);
        size += byte_len_array(&self.locale_ids);
        size += self.service_id.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.uris_version)?;
        size += write_array(stream, &self.namespace_uris)?;
        size += write_array(stream, &self.server_uris)?;
        size += write_array(stream, &self.locale_ids)?;
        size += self.service_id.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let uris_version: Option<Vec<u32>> = read_array(stream, decoding_limits)?;
        let namespace_uris: Option<Vec<UAString>> = read_array(stream, decoding_limits)?;
        let server_uris: Option<Vec<UAString>> = read_array(stream, decoding_limits)?;
        let locale_ids: Option<Vec<UAString>> = read_array(stream, decoding_limits)?;
        let service_id = u32::decode(stream, decoding_limits)?;
        Ok(SessionlessInvokeRequestType {
            uris_version,
            namespace_uris,
            server_uris,
            locale_ids,
            service_id,
        })
    }
}
