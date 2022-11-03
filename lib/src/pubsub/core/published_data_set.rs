use std::sync::Arc;

use super::DataSetWriter;

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
