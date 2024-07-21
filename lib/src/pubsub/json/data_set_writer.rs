// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use crate::pubsub::core::{self, DataSet, DataSetWriter as CoreDataSetWriter};

use super::*;

pub struct DataSetWriter {
    id: u16,
    sequence_number: u32,
    message_content_mask: JsonDataSetMessageContentMask,
    field_content_mask: DataSetFieldContentMask,
}

impl core::DataSetWriter for DataSetWriter {
    fn id(&self) -> u16 {
        self.id
    }

    fn write(&mut self, ds: &DataSet) -> Box<dyn core::DataSetMessage> {
        self.sequence_number += 1;

        let mut data_set_message = DataSetMessage::default();

        // Message headers

        if self
            .message_content_mask
            .contains(JsonDataSetMessageContentMask::Status)
        {
            // Fixme
            data_set_message.status = Some(StatusCode::Good)
        }
        if self
            .message_content_mask
            .contains(JsonDataSetMessageContentMask::SequenceNumber)
        {
            data_set_message.sequence_number = Some(self.sequence_number);
        }

        // Payload of the message depends on field content mask

        // FIXME
        data_set_message.payload = Payload::new();

        // TODO
        Box::new(data_set_message)
    }
}

impl DataSetWriter {
    pub fn new(
        id: u16,
        message_content_mask: JsonDataSetMessageContentMask,
        field_content_mask: DataSetFieldContentMask,
    ) -> Self {
        if id == 0 {
            panic!("Writer id must be 1 or greater");
        }
        Self {
            id,
            field_content_mask,
            message_content_mask,
            sequence_number: 0,
        }
    }
}

#[test]
fn write_json() {
    let message_content_mask = JsonDataSetMessageContentMask::all();
    let field_content_mask = DataSetFieldContentMask::all();

    let mut dsw = DataSetWriter::new(1, message_content_mask, field_content_mask);

    let mut ds = DataSet::default();
    let dsm = dsw.write(&ds);
}
