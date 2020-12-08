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
    node_id::NodeId,
};

#[derive(Debug, Clone, PartialEq)]
pub struct SemanticChangeStructureDataType {
    pub affected: NodeId,
    pub affected_type: NodeId,
}

impl MessageInfo for SemanticChangeStructureDataType {
    fn object_id(&self) -> ObjectId {
        ObjectId::SemanticChangeStructureDataType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<SemanticChangeStructureDataType> for SemanticChangeStructureDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.affected.byte_len();
        size += self.affected_type.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.affected.encode(stream)?;
        size += self.affected_type.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let affected = NodeId::decode(stream, decoding_limits)?;
        let affected_type = NodeId::decode(stream, decoding_limits)?;
        Ok(SemanticChangeStructureDataType {
            affected,
            affected_type,
        })
    }
}
