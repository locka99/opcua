// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, byte_string::ByteString, encoding::*, node_ids::ObjectId,
    response_header::ResponseHeader, service_types::impls::MessageInfo,
    service_types::ChannelSecurityToken,
};

#[derive(Debug, Clone, PartialEq)]
pub struct OpenSecureChannelResponse {
    pub response_header: ResponseHeader,
    pub server_protocol_version: u32,
    pub security_token: ChannelSecurityToken,
    pub server_nonce: ByteString,
}

impl MessageInfo for OpenSecureChannelResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::OpenSecureChannelResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<OpenSecureChannelResponse> for OpenSecureChannelResponse {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.response_header.byte_len();
        size += self.server_protocol_version.byte_len();
        size += self.security_token.byte_len();
        size += self.server_nonce.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.response_header.encode(stream)?;
        size += self.server_protocol_version.encode(stream)?;
        size += self.security_token.encode(stream)?;
        size += self.server_nonce.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let response_header = ResponseHeader::decode(stream, decoding_limits)?;
        let server_protocol_version = u32::decode(stream, decoding_limits)?;
        let security_token = ChannelSecurityToken::decode(stream, decoding_limits)?;
        let server_nonce = ByteString::decode(stream, decoding_limits)?;
        Ok(OpenSecureChannelResponse {
            response_header,
            server_protocol_version,
            security_token,
            server_nonce,
        })
    }
}
