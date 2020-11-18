// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_ids::ObjectId, service_types::impls::MessageInfo,
    service_types::RelativePathElement,
};

#[derive(Debug, Clone, PartialEq)]
pub struct RelativePath {
    pub elements: Option<Vec<RelativePathElement>>,
}

impl MessageInfo for RelativePath {
    fn object_id(&self) -> ObjectId {
        ObjectId::RelativePath_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<RelativePath> for RelativePath {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.elements);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.elements)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let elements: Option<Vec<RelativePathElement>> = read_array(stream, decoding_limits)?;
        Ok(RelativePath { elements })
    }
}
