// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{basic_types::*, encoding::*, node_ids::ObjectId, service_types::impls::MessageInfo};

#[derive(Debug, Clone, PartialEq)]
pub struct FilterOperand {}

impl MessageInfo for FilterOperand {
    fn object_id(&self) -> ObjectId {
        ObjectId::FilterOperand_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<FilterOperand> for FilterOperand {
    fn byte_len(&self) -> usize {
        0
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        Ok(0)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        Ok(FilterOperand {})
    }
}
