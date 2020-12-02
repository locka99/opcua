// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE
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
pub struct SubscriptionAcknowledgement {
    pub subscription_id: u32,
    pub sequence_number: u32,
}

impl MessageInfo for SubscriptionAcknowledgement {
    fn object_id(&self) -> ObjectId {
        ObjectId::SubscriptionAcknowledgement_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<SubscriptionAcknowledgement> for SubscriptionAcknowledgement {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.subscription_id.byte_len();
        size += self.sequence_number.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.subscription_id.encode(stream)?;
        size += self.sequence_number.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_limits: &DecodingLimits) -> EncodingResult<Self> {
        let subscription_id = u32::decode(stream, decoding_limits)?;
        let sequence_number = u32::decode(stream, decoding_limits)?;
        Ok(SubscriptionAcknowledgement {
            subscription_id,
            sequence_number,
        })
    }
}
