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
};

#[derive(Debug, Clone, PartialEq)]
pub struct ElementOperand {
    pub index: u32,
}

impl BinaryEncoder<ElementOperand> for ElementOperand {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.index.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.index.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let index = u32::decode(stream, decoding_limits)?;
        Ok(ElementOperand {
            index,
        })
    }
}
