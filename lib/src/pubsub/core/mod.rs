use std::str::FromStr;

use serde::{de, Deserialize, Deserializer};

pub mod data_set_message;
pub mod data_set_meta_data;
pub mod json_writer;
pub mod network_message;
pub mod published_data_set;
pub mod writer_group;

pub use self::writer_group::*;

pub struct DataSetClassId {}

pub struct DataSetClass {}

pub struct DataSet {}

pub(crate) fn deserialize_from_str_option<'de, S, D>(deserializer: D) -> Result<Option<S>, D::Error>
where
    S: FromStr,
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    S::from_str(&s)
        .map(|s| Some(s))
        .map_err(|_e| de::Error::custom("Cannot parse from string"))
}

pub(crate) fn deserialize_from_str<'de, S, D>(deserializer: D) -> Result<S, D::Error>
where
    S: FromStr,
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    S::from_str(&s).map_err(|_e| de::Error::custom("Cannot parse from string"))
}

pub trait DataSetWriter {
    fn write(&self, ds: DataSet);
}

trait DataSetReader {
    fn read(&self) -> Option<DataSet>;
}
