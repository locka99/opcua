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
    service_types::enums::MessageSecurityMode,
    service_types::EndpointDescription,
    service_types::KeyValuePair,
};

#[derive(Debug, Clone, PartialEq)]
pub struct PubSubGroupDataType {
    pub name: UAString,
    pub enabled: bool,
    pub security_mode: MessageSecurityMode,
    pub security_group_id: UAString,
    pub security_key_services: Option<Vec<EndpointDescription>>,
    pub max_network_message_size: u32,
    pub group_properties: Option<Vec<KeyValuePair>>,
}

impl MessageInfo for PubSubGroupDataType {
    fn object_id(&self) -> ObjectId {
        ObjectId::PubSubGroupDataType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<PubSubGroupDataType> for PubSubGroupDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.name.byte_len();
        size += self.enabled.byte_len();
        size += self.security_mode.byte_len();
        size += self.security_group_id.byte_len();
        size += byte_len_array(&self.security_key_services);
        size += self.max_network_message_size.byte_len();
        size += byte_len_array(&self.group_properties);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.name.encode(stream)?;
        size += self.enabled.encode(stream)?;
        size += self.security_mode.encode(stream)?;
        size += self.security_group_id.encode(stream)?;
        size += write_array(stream, &self.security_key_services)?;
        size += self.max_network_message_size.encode(stream)?;
        size += write_array(stream, &self.group_properties)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let name = UAString::decode(stream, decoding_limits)?;
        let enabled = bool::decode(stream, decoding_limits)?;
        let security_mode = MessageSecurityMode::decode(stream, decoding_limits)?;
        let security_group_id = UAString::decode(stream, decoding_limits)?;
        let security_key_services: Option<Vec<EndpointDescription>> = read_array(stream, decoding_limits)?;
        let max_network_message_size = u32::decode(stream, decoding_limits)?;
        let group_properties: Option<Vec<KeyValuePair>> = read_array(stream, decoding_limits)?;
        Ok(PubSubGroupDataType {
            name,
            enabled,
            security_mode,
            security_group_id,
            security_key_services,
            max_network_message_size,
            group_properties,
        })
    }
}
