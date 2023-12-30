use std::{fmt::Display, str::FromStr, sync::Arc};

use serde::{de, Deserialize, Deserializer, Serializer};

use crate::types::*;

mod data_set_message;
mod data_set_writer;
mod network_message;

pub use data_set_message::*;
pub use data_set_writer::*;
pub use network_message::*;

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
    if let Ok(s) = Deserialize::deserialize(deserializer) {
        Ok(Some(s))
    } else {
        Ok(None)
    }
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
