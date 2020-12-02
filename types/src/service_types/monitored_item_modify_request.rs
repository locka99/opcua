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
    service_types::MonitoringParameters,
};

#[derive(Debug, Clone, PartialEq)]
pub struct MonitoredItemModifyRequest {
    pub monitored_item_id: u32,
    pub requested_parameters: MonitoringParameters,
}

impl MessageInfo for MonitoredItemModifyRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::MonitoredItemModifyRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<MonitoredItemModifyRequest> for MonitoredItemModifyRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.monitored_item_id.byte_len();
        size += self.requested_parameters.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.monitored_item_id.encode(stream)?;
        size += self.requested_parameters.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let monitored_item_id = u32::decode(stream, decoding_limits)?;
        let requested_parameters = MonitoringParameters::decode(stream, decoding_limits)?;
        Ok(MonitoredItemModifyRequest {
            monitored_item_id,
            requested_parameters,
        })
    }
}
