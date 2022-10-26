use std::sync::Arc;

use crate::types::*;

pub struct DataSetClassId {}

pub struct DataSetClass {}

pub struct DataSet {}

pub struct WriterGroup {
    pub writers: Vec<Arc<Box<dyn DataSetWriter>>>,
}

impl Default for WriterGroup {
    fn default() -> Self {
        Self {
            writers: Vec::new(),
        }
    }
}

impl WriterGroup {
    pub fn add(&mut self, writer: Arc<Box<dyn DataSetWriter>>) {
        self.writers.push(writer);
    }
}

pub struct PublishedDataSet {
    // 0 or more writers are associated with the dataset
    pub writers: Vec<Arc<Box<dyn DataSetWriter>>>,
}

impl Default for PublishedDataSet {
    fn default() -> Self {
        Self {
            writers: Vec::new(),
        }
    }
}

impl PublishedDataSet {
    pub fn add(&mut self, writer: Arc<Box<dyn DataSetWriter>>) {
        self.writers.push(writer);
    }
}

pub struct NetworkMessage {
    messages: Vec<DataSetMessage>,
}

impl Default for NetworkMessage {
    fn default() -> Self {
        Self {
            messages: Vec::new(),
        }
    }
}

impl NetworkMessage {}

pub struct DataSetMessage {}

impl DataSetMessage {}

pub trait DataSetWriter {
    fn write(&self, ds: DataSet);
}

trait DataSetReader {
    fn read(&self) -> Option<DataSet>;
}

mod json_writer;