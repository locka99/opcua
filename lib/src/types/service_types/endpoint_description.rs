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
    basic_types::*, byte_string::ByteString, encoding::*, node_ids::ObjectId,
    service_types::enums::MessageSecurityMode, service_types::impls::MessageInfo,
    service_types::ApplicationDescription, service_types::UserTokenPolicy, string::UAString,
};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq)]
pub struct EndpointDescription {
    pub endpoint_url: UAString,
    pub server: ApplicationDescription,
    pub server_certificate: ByteString,
    pub security_mode: MessageSecurityMode,
    pub security_policy_uri: UAString,
    pub user_identity_tokens: Option<Vec<UserTokenPolicy>>,
    pub transport_profile_uri: UAString,
    pub security_level: u8,
}

impl MessageInfo for EndpointDescription {
    fn object_id(&self) -> ObjectId {
        ObjectId::EndpointDescription_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<EndpointDescription> for EndpointDescription {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.endpoint_url.byte_len();
        size += self.server.byte_len();
        size += self.server_certificate.byte_len();
        size += self.security_mode.byte_len();
        size += self.security_policy_uri.byte_len();
        size += byte_len_array(&self.user_identity_tokens);
        size += self.transport_profile_uri.byte_len();
        size += self.security_level.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.endpoint_url.encode(stream)?;
        size += self.server.encode(stream)?;
        size += self.server_certificate.encode(stream)?;
        size += self.security_mode.encode(stream)?;
        size += self.security_policy_uri.encode(stream)?;
        size += write_array(stream, &self.user_identity_tokens)?;
        size += self.transport_profile_uri.encode(stream)?;
        size += self.security_level.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let endpoint_url = UAString::decode(stream, decoding_options)?;
        let server = ApplicationDescription::decode(stream, decoding_options)?;
        let server_certificate = ByteString::decode(stream, decoding_options)?;
        let security_mode = MessageSecurityMode::decode(stream, decoding_options)?;
        let security_policy_uri = UAString::decode(stream, decoding_options)?;
        let user_identity_tokens: Option<Vec<UserTokenPolicy>> =
            read_array(stream, decoding_options)?;
        let transport_profile_uri = UAString::decode(stream, decoding_options)?;
        let security_level = u8::decode(stream, decoding_options)?;
        Ok(EndpointDescription {
            endpoint_url,
            server,
            server_certificate,
            security_mode,
            security_policy_uri,
            user_identity_tokens,
            transport_profile_uri,
            security_level,
        })
    }
}
