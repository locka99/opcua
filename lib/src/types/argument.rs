// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::io::{Read, Write};

use crate::types::{
    encoding::*, localized_text::LocalizedText, node_id::NodeId, status_codes::StatusCode,
    string::UAString,
};

// From OPC UA Part 3 - Address Space Model 1.03 Specification
//
// This Structured DataType defines a Method input or output argument specification. It is for
// example used in the input and output argument Properties for Methods. Its elements are described in
// Table23

#[derive(Clone, Debug, PartialEq)]
pub struct Argument {
    pub name: UAString,
    pub data_type: NodeId,
    pub value_rank: i32,
    pub array_dimensions: Option<Vec<u32>>,
    pub description: LocalizedText,
}

impl BinaryEncoder<Argument> for Argument {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.name.byte_len();
        size += self.data_type.byte_len();
        size += self.value_rank.byte_len();
        size += byte_len_array(&self.array_dimensions);
        size += self.description.byte_len();
        size
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.name.encode(stream)?;
        size += self.data_type.encode(stream)?;
        size += self.value_rank.encode(stream)?;
        // Encode the array dimensions
        if self.value_rank > 0 {
            if let Some(ref array_dimensions) = self.array_dimensions {
                if self.value_rank as usize != array_dimensions.len() {
                    error!("The array dimensions {} of the Argument should match value rank {} and they don't", array_dimensions.len(), self.value_rank);
                    return Err(StatusCode::BadDataEncodingInvalid);
                }
                size += write_array(stream, &self.array_dimensions)?;
            } else {
                error!("The array dimensions are expected in the Argument matching value rank {} and they aren't", self.value_rank);
                return Err(StatusCode::BadDataEncodingInvalid);
            }
        } else {
            size += write_u32(stream, 0u32)?;
        }

        size += self.description.encode(stream)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let name = UAString::decode(stream, decoding_options)?;
        let data_type = NodeId::decode(stream, decoding_options)?;
        let value_rank = i32::decode(stream, decoding_options)?;
        // Decode array dimensions
        let array_dimensions: Option<Vec<u32>> = read_array(stream, decoding_options)?;
        if let Some(ref array_dimensions) = array_dimensions {
            if value_rank > 0 && value_rank as usize != array_dimensions.len() {
                error!("The array dimensions {} of the Argument should match value rank {} and they don't", array_dimensions.len(), value_rank);
                return Err(StatusCode::BadDataEncodingInvalid);
            }
        }
        let description = LocalizedText::decode(stream, decoding_options)?;
        Ok(Argument {
            name,
            data_type,
            value_rank,
            array_dimensions,
            description,
        })
    }
}
