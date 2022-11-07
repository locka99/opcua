use crate::pubsub::core::DataSetWriter;
use std::sync::Arc;

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
