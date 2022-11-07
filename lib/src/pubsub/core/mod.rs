use std::{fmt::Display, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serializer};

use crate::types::StatusCode;

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

pub struct DataSetClass {}

pub trait DataSetWriter {
    fn write(&self, ds: data_set::DataSet);
}

trait DataSetReader {
    fn read(&self) -> Option<data_set::DataSet>;
}
