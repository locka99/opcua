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
    guid::Guid,
    service_types::enums::UadpNetworkMessageContentMask,
    service_types::enums::UadpDataSetMessageContentMask,
};

#[derive(Debug, Clone, PartialEq)]
pub struct UadpDataSetReaderMessageDataType {
    pub group_version: u32,
    pub network_message_number: u16,
    pub data_set_offset: u16,
    pub data_set_class_id: Guid,
    pub network_message_content_mask: UadpNetworkMessageContentMask,
    pub data_set_message_content_mask: UadpDataSetMessageContentMask,
    pub publishing_interval: f64,
    pub receive_offset: f64,
    pub processing_offset: f64,
}

impl BinaryEncoder<UadpDataSetReaderMessageDataType> for UadpDataSetReaderMessageDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.group_version.byte_len();
        size += self.network_message_number.byte_len();
        size += self.data_set_offset.byte_len();
        size += self.data_set_class_id.byte_len();
        size += self.network_message_content_mask.byte_len();
        size += self.data_set_message_content_mask.byte_len();
        size += self.publishing_interval.byte_len();
        size += self.receive_offset.byte_len();
        size += self.processing_offset.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.group_version.encode(stream)?;
        size += self.network_message_number.encode(stream)?;
        size += self.data_set_offset.encode(stream)?;
        size += self.data_set_class_id.encode(stream)?;
        size += self.network_message_content_mask.encode(stream)?;
        size += self.data_set_message_content_mask.encode(stream)?;
        size += self.publishing_interval.encode(stream)?;
        size += self.receive_offset.encode(stream)?;
        size += self.processing_offset.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let group_version = u32::decode(stream, decoding_limits)?;
        let network_message_number = u16::decode(stream, decoding_limits)?;
        let data_set_offset = u16::decode(stream, decoding_limits)?;
        let data_set_class_id = Guid::decode(stream, decoding_limits)?;
        let network_message_content_mask = UadpNetworkMessageContentMask::decode(stream, decoding_limits)?;
        let data_set_message_content_mask = UadpDataSetMessageContentMask::decode(stream, decoding_limits)?;
        let publishing_interval = f64::decode(stream, decoding_limits)?;
        let receive_offset = f64::decode(stream, decoding_limits)?;
        let processing_offset = f64::decode(stream, decoding_limits)?;
        Ok(UadpDataSetReaderMessageDataType {
            group_version,
            network_message_number,
            data_set_offset,
            data_set_class_id,
            network_message_content_mask,
            data_set_message_content_mask,
            publishing_interval,
            receive_offset,
            processing_offset,
        })
    }
}
