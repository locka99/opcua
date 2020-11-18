// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_id::ExpandedNodeId, node_ids::ObjectId,
    service_types::impls::MessageInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct BrowsePathTarget {
    pub target_id: ExpandedNodeId,
    pub remaining_path_index: u32,
}

impl MessageInfo for BrowsePathTarget {
    fn object_id(&self) -> ObjectId {
        ObjectId::BrowsePathTarget_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<BrowsePathTarget> for BrowsePathTarget {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.target_id.byte_len();
        size += self.remaining_path_index.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.target_id.encode(stream)?;
        size += self.remaining_path_index.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let target_id = ExpandedNodeId::decode(stream, decoding_limits)?;
        let remaining_path_index = u32::decode(stream, decoding_limits)?;
        Ok(BrowsePathTarget {
            target_id,
            remaining_path_index,
        })
    }
}
