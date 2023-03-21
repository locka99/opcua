use crate::pubsub::core::{self, DataSet};

use super::data_set_message::*;

struct JsonWriter {
    id: u16,
}

impl DataSetWriter for JsonWriter {
    fn id(&self) -> u16 {
        self.id
    }

    fn write(&self, ds: &DataSet) -> Box<dyn core::DataSetMessage> {
        // TODO
        unimplemented!()
    }
}

impl JsonWriter {
    pub fn new(id: u16) -> Self {
        if id == 0 {
            panic!("Writer id must be 1 or greater");
        }
        Self { id }
    }
}

#[test]
fn write_json() {
    let dsw = JsonWriter::new(1);

    let ds = DataSet::default();

    let dsm = ds.write(ds);
}
