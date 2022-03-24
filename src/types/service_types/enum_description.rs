// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock
//
// This file was autogenerated from Opc.Ua.Types.bsd by tools/schema/gen_types.js
//
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]
use std::io::{Read, Write};
#[allow(unused_imports)]
use crate::{
    encoding::*,
    basic_types::*,
    node_id::NodeId,
    qualified_name::QualifiedName,
    service_types::EnumDefinition,
};

#[derive(Debug, Clone, PartialEq)]
pub struct EnumDescription {
    pub data_type_id: NodeId,
    pub name: QualifiedName,
    pub enum_definition: EnumDefinition,
    pub built_in_type: u8,
}

impl BinaryEncoder<EnumDescription> for EnumDescription {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.data_type_id.byte_len();
        size += self.name.byte_len();
        size += self.enum_definition.byte_len();
        size += self.built_in_type.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.data_type_id.encode(stream)?;
        size += self.name.encode(stream)?;
        size += self.enum_definition.encode(stream)?;
        size += self.built_in_type.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let data_type_id = NodeId::decode(stream, decoding_options)?;
        let name = QualifiedName::decode(stream, decoding_options)?;
        let enum_definition = EnumDefinition::decode(stream, decoding_options)?;
        let built_in_type = u8::decode(stream, decoding_options)?;
        Ok(EnumDescription {
            data_type_id,
            name,
            enum_definition,
            built_in_type,
        })
    }
}