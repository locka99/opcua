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
    date_time::DateTime,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ChannelSecurityToken {
    pub channel_id: u32,
    pub token_id: u32,
    pub created_at: DateTime,
    pub revised_lifetime: u32,
}

impl MessageInfo for ChannelSecurityToken {
    fn object_id(&self) -> ObjectId {
        ObjectId::ChannelSecurityToken_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<ChannelSecurityToken> for ChannelSecurityToken {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.channel_id.byte_len();
        size += self.token_id.byte_len();
        size += self.created_at.byte_len();
        size += self.revised_lifetime.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.channel_id.encode(stream)?;
        size += self.token_id.encode(stream)?;
        size += self.created_at.encode(stream)?;
        size += self.revised_lifetime.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let channel_id = u32::decode(stream, decoding_options)?;
        let token_id = u32::decode(stream, decoding_options)?;
        let created_at = DateTime::decode(stream, decoding_options)?;
        let revised_lifetime = u32::decode(stream, decoding_options)?;
        Ok(ChannelSecurityToken {
            channel_id,
            token_id,
            created_at,
            revised_lifetime,
        })
    }
}
