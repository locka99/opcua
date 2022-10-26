use std::sync::Arc;

use serde::{Serialize, Deserialize};
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


// Optional fields are determined by NetworkMessageContentMask
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkMessage {
    /// A globally unique identifier for the message, e.g. a guid. Converted to a string for JSON.
    #[serde(deserialize_with = "deserialize_from_str")]
    message_id: Guid,
    /// Value which is always "ua-data"
    message_type: String,
    /// Publisher id which is a u32 converted to a string for JSON
    #[serde(deserialize_with = "deserialize_from_str")]
    publisher_id: Option<u32>,
    /// Dataset class id associated with the datasets in the network message. A guid converted to a string for JSON
    #[serde(deserialize_with = "deserialize_from_str")]
    data_set_class_id: Option<Guid>,
    /// An array of DataSetMessages. Can also be serialized as an object in JSON if SingleDataSetMessage bit is set
    messages: Vec<DataSetMessage>,
}

impl Default for NetworkMessage {
    fn default() -> Self {
        Self {
            message_type: "ua-data".into(),
            ..Default::default()
        }
    }
}

impl NetworkMessage {}

/// Optional fields are determined by DataSetMessageContentMask
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DataSetMessage {
    data_set_writer_id: Option<String>,
    data_set_writer_name: Option<String>,
    sequence_number: Option<u32>,
    // FIX ME
    #[serde(skip)] 
    meta_data_version: Option<ConfigurationVersionDataType>,
    #[serde(deserialize_with = "deserialize_from_str")]
    timestamp: Option<DateTime>,
    status: Option<StatusCode>,
    /// Possible values "ua-keyframe", "ua-deltaframe", "ua-event", "ua-keepalive"
    message_type: Option<String>,
    payload: HashMap<String, Variant>,
}

impl Default for DataSetMessage {
    fn default() -> Self {
        Self {
            ..Default::default()
        }
    }
}

impl DataSetMessage {}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct DataSetMetaData {
    message_id: String,
    message_type: String,
    publisher_id: String,
    data_set_writer_id: u16,
    // FIXME
    #[serde(skip)] 
    meta_data: DataSetMetaDataType
}

impl Default for DataSetMetaData {
    fn default() -> Self {
        Self {
            meta_data:DataSetMetaDataType {
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

pub trait DataSetWriter {
    fn write(&self, ds: DataSet);
}

trait DataSetReader {
    fn read(&self) -> Option<DataSet>;
}

mod json_writer;
