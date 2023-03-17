use super::{data_set::*, *};

struct JsonWriter {
    id: u16
}

impl DataSetWriter for JsonWriter {

    fn id(&self) -> u16 {
        self.id
    }

    fn write(&self, ds: &data_set::DataSet) -> DataSetMessage {
        // TODO
        unimplemented!()
    }
}

impl JsonWriter {
    pub fn new(id: u16) -> Self {
        Self {
            id
        }
    }
}
