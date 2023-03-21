use serd_json::Value;

use crate::pubsub::core::{self, DataSet};

use super::data_set_message::*;

struct JsonWriter {
    id: u16,
    sequence_number: u32,
    message_content_mask: JsonDataSetMessageContentMask,
    field_content_mask: DataSetFieldContentMask,
}

impl core::DataSetWriter for JsonWriter {
    fn id(&self) -> u16 {
        self.id
    }

    fn write(&mut self, ds: &DataSet) -> Box<dyn core::DataSetMessage> {
        self.sequence_number += 1;

        let mut data_set_message = DataSetMessage::default();

        // Message headers

        if message_content_mask & JsonDataSetMessageContentMask::StatusCode {
            // Fixme
            data_set_message.status = Some(StatusCode::Good)
        }
        if message_content_mask & JsonDataSetMessageContentMask::SequenceNumber {
            data_set_message.sequence_number = Some(self.sequence_number);
        }

        // Payload of the message depends on field content mask

        // FIXME
        data_set_message.payload = if field_content_mask & DataSetFieldContentMask::RawData {
            Representation::RawValue(Value::Null)
        } else if field_content_mask
            & (DataSetFieldContentMask::SourceTimestamp
                | DataSetFieldContentMask::ServerTimestamp
                | DataSetFieldContentMask::SourcePicoSeconds
                | DataSetFieldContentMask::ServerPicoSeconds)
        {
            Representation::DataValue(DataValue::default())
        } else {
            Representation::Variant(Variant::Empty)
        };

        // TODO
        Box::new(data_set_message)
    }
}

impl JsonWriter {
    pub fn new(id: u16, data_set_field_content_mask: DataSetFieldContentMask) -> Self {
        if id == 0 {
            panic!("Writer id must be 1 or greater");
        }
        Self {
            id,
            data_set_field_content_mask,
            sequence_number: 0,
        }
    }
}

#[test]
fn write_json() {
    let content_mask = DataSetFieldContentMask::all();

    let dsw = JsonWriter::new(1);

    let ds = DataSet::default();

    let dsm = ds.write(ds);
}
