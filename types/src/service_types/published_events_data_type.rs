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
    node_id::NodeId,
    service_types::SimpleAttributeOperand,
    service_types::ContentFilter,
};

#[derive(Debug, Clone, PartialEq)]
pub struct PublishedEventsDataType {
    pub event_notifier: NodeId,
    pub selected_fields: Option<Vec<SimpleAttributeOperand>>,
    pub filter: ContentFilter,
}

impl BinaryEncoder<PublishedEventsDataType> for PublishedEventsDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.event_notifier.byte_len();
        size += byte_len_array(&self.selected_fields);
        size += self.filter.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.event_notifier.encode(stream)?;
        size += write_array(stream, &self.selected_fields)?;
        size += self.filter.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let event_notifier = NodeId::decode(stream, decoding_limits)?;
        let selected_fields: Option<Vec<SimpleAttributeOperand>> = read_array(stream, decoding_limits)?;
        let filter = ContentFilter::decode(stream, decoding_limits)?;
        Ok(PublishedEventsDataType {
            event_notifier,
            selected_fields,
            filter,
        })
    }
}
