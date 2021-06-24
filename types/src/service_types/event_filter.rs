// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    encoding::*,
    basic_types::*,
    service_types::SimpleAttributeOperand,
    service_types::ContentFilter,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventFilter {
    pub select_clauses: Option<Vec<SimpleAttributeOperand>>,
    pub where_clause: ContentFilter,
}

impl BinaryEncoder<EventFilter> for EventFilter {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.select_clauses);
        size += self.where_clause.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.select_clauses)?;
        size += self.where_clause.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let select_clauses: Option<Vec<SimpleAttributeOperand>> = read_array(stream, decoding_options)?;
        let where_clause = ContentFilter::decode(stream, decoding_options)?;
        Ok(EventFilter {
            select_clauses,
            where_clause,
        })
    }
}
