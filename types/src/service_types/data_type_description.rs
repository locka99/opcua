// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_id::NodeId, node_ids::ObjectId,
    qualified_name::QualifiedName, service_types::impls::MessageInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct DataTypeDescription {
    pub data_type_id: NodeId,
    pub name: QualifiedName,
}

impl MessageInfo for DataTypeDescription {
    fn object_id(&self) -> ObjectId {
        ObjectId::DataTypeDescription_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<DataTypeDescription> for DataTypeDescription {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.data_type_id.byte_len();
        size += self.name.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.data_type_id.encode(stream)?;
        size += self.name.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let data_type_id = NodeId::decode(stream, decoding_limits)?;
        let name = QualifiedName::decode(stream, decoding_limits)?;
        Ok(DataTypeDescription { data_type_id, name })
    }
}
