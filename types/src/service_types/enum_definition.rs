// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{basic_types::*, encoding::*, service_types::EnumField};

#[derive(Debug, Clone, PartialEq)]
pub struct EnumDefinition {
    pub fields: Option<Vec<EnumField>>,
}

impl BinaryEncoder<EnumDefinition> for EnumDefinition {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.fields);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.fields)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let fields: Option<Vec<EnumField>> = read_array(stream, decoding_limits)?;
        Ok(EnumDefinition { fields })
    }
}
