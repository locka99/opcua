// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_id::NodeId, node_ids::ObjectId,
    service_types::enums::BrowseDirection, service_types::impls::MessageInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct BrowseDescription {
    pub node_id: NodeId,
    pub browse_direction: BrowseDirection,
    pub reference_type_id: NodeId,
    pub include_subtypes: bool,
    pub node_class_mask: u32,
    pub result_mask: u32,
}

impl MessageInfo for BrowseDescription {
    fn object_id(&self) -> ObjectId {
        ObjectId::BrowseDescription_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<BrowseDescription> for BrowseDescription {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.node_id.byte_len();
        size += self.browse_direction.byte_len();
        size += self.reference_type_id.byte_len();
        size += self.include_subtypes.byte_len();
        size += self.node_class_mask.byte_len();
        size += self.result_mask.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.node_id.encode(stream)?;
        size += self.browse_direction.encode(stream)?;
        size += self.reference_type_id.encode(stream)?;
        size += self.include_subtypes.encode(stream)?;
        size += self.node_class_mask.encode(stream)?;
        size += self.result_mask.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let node_id = NodeId::decode(stream, decoding_limits)?;
        let browse_direction = BrowseDirection::decode(stream, decoding_limits)?;
        let reference_type_id = NodeId::decode(stream, decoding_limits)?;
        let include_subtypes = bool::decode(stream, decoding_limits)?;
        let node_class_mask = u32::decode(stream, decoding_limits)?;
        let result_mask = u32::decode(stream, decoding_limits)?;
        Ok(BrowseDescription {
            node_id,
            browse_direction,
            reference_type_id,
            include_subtypes,
            node_class_mask,
            result_mask,
        })
    }
}
