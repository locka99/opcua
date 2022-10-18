use crate::types::*;

pub struct DataSetClassId {}

pub struct DataSetClass {}

pub struct DataSet {}

pub struct PublishedDataSet {}

pub struct DataSetMessage {}

pub struct NetworkMessage {}

pub trait DataSetWriter {
    fn write(&self, ds: DataSet);
}

trait DataSetReader {
    fn read(&self) -> Option<DataSet>;
}
