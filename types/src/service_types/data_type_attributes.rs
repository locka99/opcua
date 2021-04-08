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
    localized_text::LocalizedText,
};

#[derive(Debug, Clone, PartialEq)]
pub struct DataTypeAttributes {
    pub specified_attributes: u32,
    pub display_name: LocalizedText,
    pub description: LocalizedText,
    pub write_mask: u32,
    pub user_write_mask: u32,
    pub is_abstract: bool,
}

impl BinaryEncoder<DataTypeAttributes> for DataTypeAttributes {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.specified_attributes.byte_len();
        size += self.display_name.byte_len();
        size += self.description.byte_len();
        size += self.write_mask.byte_len();
        size += self.user_write_mask.byte_len();
        size += self.is_abstract.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.specified_attributes.encode(stream)?;
        size += self.display_name.encode(stream)?;
        size += self.description.encode(stream)?;
        size += self.write_mask.encode(stream)?;
        size += self.user_write_mask.encode(stream)?;
        size += self.is_abstract.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let specified_attributes = u32::decode(stream, decoding_options)?;
        let display_name = LocalizedText::decode(stream, decoding_options)?;
        let description = LocalizedText::decode(stream, decoding_options)?;
        let write_mask = u32::decode(stream, decoding_options)?;
        let user_write_mask = u32::decode(stream, decoding_options)?;
        let is_abstract = bool::decode(stream, decoding_options)?;
        Ok(DataTypeAttributes {
            specified_attributes,
            display_name,
            description,
            write_mask,
            user_write_mask,
            is_abstract,
        })
    }
}
