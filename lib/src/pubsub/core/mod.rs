use crate::types::*;

pub struct DataSet {}

pub struct PUblishedDataSet {}

pub struct DataSetMessage {}

pub struct NetworkMessage {}

pub struct DataSetWriter {
    settings: bool, // placeholder for settings
}

pub struct DataSetClass {}

pub struct DataSetClassId {}

impl DataSetWriter {
    pub fn write(&self, ds: DataSet) -> DataSetMessage {
        DataSetMessage {}
    }
}

struct DataSetReader {}

impl DataSetReader {
    pub fn read(&self) -> Option<bool> {
        None
    }
}
