use crate::types::*;

pub struct DataSetClassId {}

pub struct DataSetClass {}

pub struct DataSet {}

pub struct PublishedDataSet {
    // 0 or more writers are associated with the dataset
    writers: Vec<Arc<Box<dyn DataSetWriter>>>
}

impl Default for PublishedDataSet {
    fn default() -> Self {
        Self {
            writers: Vec::new()
        }
    }


}

impl PublishedDataSet {

}

pub struct NetworkMessage {
    messages: Vec<DataSetMessage>
}

impl Default for NetworkMessage {
    fn default() -> Self {
        Self {
            messages: Vec::new()
        }
    }
}

impl NetworkMessage {

}

pub struct DataSetMessage {}

impl DataSetMessage {

}

pub trait DataSetWriter {
    fn write(&self, ds: DataSet);
}

trait DataSetReader {
    fn read(&self) -> Option<DataSet>;
}
