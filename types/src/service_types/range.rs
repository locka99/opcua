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
};

#[derive(Debug, Clone, PartialEq)]
pub struct Range {
    pub low: f64,
    pub high: f64,
}

impl MessageInfo for Range {
    fn object_id(&self) -> ObjectId {
        ObjectId::Range_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<Range> for Range {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.low.byte_len();
        size += self.high.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.low.encode(stream)?;
        size += self.high.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let low = f64::decode(stream, decoding_limits)?;
        let high = f64::decode(stream, decoding_limits)?;
        Ok(Range {
            low,
            high,
        })
    }
}
