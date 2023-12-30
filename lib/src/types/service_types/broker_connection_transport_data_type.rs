// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock
//
// This file was autogenerated from Opc.Ua.Types.bsd by tools/schema/gen_types.js
//
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]
#[allow(unused_imports)]
use crate::types::{basic_types::*, encoding::*, string::UAString};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq)]
pub struct BrokerConnectionTransportDataType {
    pub resource_uri: UAString,
    pub authentication_profile_uri: UAString,
}

impl BinaryEncoder<BrokerConnectionTransportDataType> for BrokerConnectionTransportDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.resource_uri.byte_len();
        size += self.authentication_profile_uri.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.resource_uri.encode(stream)?;
        size += self.authentication_profile_uri.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let resource_uri = UAString::decode(stream, decoding_options)?;
        let authentication_profile_uri = UAString::decode(stream, decoding_options)?;
        Ok(BrokerConnectionTransportDataType {
            resource_uri,
            authentication_profile_uri,
        })
    }
}
