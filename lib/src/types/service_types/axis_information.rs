// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock
//
// This file was autogenerated from Opc.Ua.Types.bsd by tools/schema/gen_types.js
//
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]
#[allow(unused_imports)]
use crate::types::{
    basic_types::*, encoding::*, localized_text::LocalizedText, node_ids::ObjectId,
    service_types::enums::AxisScaleEnumeration, service_types::impls::MessageInfo,
    service_types::EUInformation, service_types::Range,
};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq)]
pub struct AxisInformation {
    pub engineering_units: EUInformation,
    pub eu_range: Range,
    pub title: LocalizedText,
    pub axis_scale_type: AxisScaleEnumeration,
    pub axis_steps: Option<Vec<f64>>,
}

impl MessageInfo for AxisInformation {
    fn object_id(&self) -> ObjectId {
        ObjectId::AxisInformation_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<AxisInformation> for AxisInformation {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.engineering_units.byte_len();
        size += self.eu_range.byte_len();
        size += self.title.byte_len();
        size += self.axis_scale_type.byte_len();
        size += byte_len_array(&self.axis_steps);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.engineering_units.encode(stream)?;
        size += self.eu_range.encode(stream)?;
        size += self.title.encode(stream)?;
        size += self.axis_scale_type.encode(stream)?;
        size += write_array(stream, &self.axis_steps)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let engineering_units = EUInformation::decode(stream, decoding_options)?;
        let eu_range = Range::decode(stream, decoding_options)?;
        let title = LocalizedText::decode(stream, decoding_options)?;
        let axis_scale_type = AxisScaleEnumeration::decode(stream, decoding_options)?;
        let axis_steps: Option<Vec<f64>> = read_array(stream, decoding_options)?;
        Ok(AxisInformation {
            engineering_units,
            eu_range,
            title,
            axis_scale_type,
            axis_steps,
        })
    }
}
