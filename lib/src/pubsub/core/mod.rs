use std::{fmt::Display, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serializer};

use crate::client::prelude::*;

use crate::pubsub::core::data_set_message::DataSetMessage;

pub mod data_set;
pub mod data_set_message;
pub mod data_set_meta_data;
pub mod json_writer;
pub mod network_message;
pub mod published_data_set;
pub mod writer_group;

pub mod message_type {
    pub const DATA: &'static str = "ua-data";
    pub const METADATA: &'static str = "ua-metadata";
    pub const KEYFRAME: &'static str = "ua-keyframe";
    pub const DELTAFRAME: &'static str = "ua-deltaframe";
    pub const EVENT: &'static str = "ua-event";
    pub const KEEPALIVE: &'static str = "ua-keepalive";
}

fn deserialize_from_str_option<'de, S, D>(deserializer: D) -> Result<Option<S>, D::Error>
where
    S: FromStr,
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    S::from_str(&s)
        .map(|s| Some(s))
        .map_err(|_e| de::Error::custom("Cannot parse from string"))
}

fn deserialize_status_code_option<'de, D>(deserializer: D) -> Result<Option<StatusCode>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Deserialize::deserialize(deserializer)?;
    Ok(Some(s))
}

fn deserialize_from_str<'de, S, D>(deserializer: D) -> Result<S, D::Error>
where
    S: FromStr,
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    S::from_str(&s).map_err(|_e| de::Error::custom("Cannot parse from string"))
}

fn serialize_to_str<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Display,
    S: Serializer,
{
    serializer.collect_str(value)
}

pub struct DataSetClassId {}

/// Template declaring the content of of a DataSet
pub struct DataSetClass {}

/// An entity creating DataSetMessages from DataSets and publishing them through a Message Oriented Middleware.
/// A DataSetWriter encodes a DataSet to a DataSetMessage and includes the DataSetMessage into a NetworkMessage for publishing
/// through a Message Oriented Middleware
pub trait DataSetWriter {
    /// The name of the dataset writer
    fn name(&self) -> String {
        String::new()
    }
    /// The enabled state of the dataset writer
    fn enabled(&self) -> bool {
        true
    }
    /// Returns the unique id of the dataset writer for a published dataset. Defined in 6.2.3.1
    fn id(&self) -> u16;
    /// Defined in 6.2.3.2
    fn content_mask(&self) -> DataSetFieldContentMask {
        DataSetFieldContentMask::RawData
    }
    // Defined in 6.2.3.3
    fn key_frame_count(&self) -> u32 {
        0
    }
    /// The name of the corresponding published data set
    fn data_set_name(&self) -> String {
        String::new()
    }
    // Defined in 6.2.3.4
    fn data_set_properties(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    //  Defined in 6.2.3.5.2
    //  fn transport_settings(&self) -> DataSetWriterTransportDataType {
    //    DataSetWriterTransportDataType:
    //  }

    //  Defined in 6.2.3.5.3
    //  fn message_data_type(&self) -> DataSetWriterMessageDataType {
    //
    //  }

    /// Writes a data set as a data set message
    fn write(&self, ds: &data_set::DataSet) -> DataSetMessage;
}

/// An entity receiving DataSetMessages from a MessageOrientedMiddleware. It extracts a DataSetMessage from a NetworkMessage
/// // and decodes the DataSetMessage to a DataSet for further processing in the Subscriber
trait DataSetReader {
    /// Reads a data set message to a data set
    fn read(&self, dsm: &data_set_message::DataSetMessage) -> Option<data_set::DataSet>;
}
