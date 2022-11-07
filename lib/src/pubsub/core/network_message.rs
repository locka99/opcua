use serde::{Serialize, Deserialize};

use crate::types::*;

use super::{
    data_set_message::DataSetMessage,
    deserialize_from_str, deserialize_from_str_option
};

// Optional fields are determined by NetworkMessageContentMask
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkMessage {
    /// A globally unique identifier for the message, e.g. a guid. Converted to a string for JSON.
    #[serde(deserialize_with = "deserialize_from_str")]
    message_id: Guid,
    /// Message type value is always "ua-data"
    message_type: String,
    /// Publisher id which is a u32 converted to a string for JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_from_str_option")]
    publisher_id: Option<u32>,
    /// Dataset class id associated with the datasets in the network message. A guid converted to a string for JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_from_str_option")]
    data_set_class_id: Option<Guid>,
    /// An array of DataSetMessages. Can also be serialized as an object in JSON if SingleDataSetMessage bit is set
    messages: Vec<DataSetMessage>,
}

impl Default for NetworkMessage {
    fn default() -> Self {
        Self {
            message_id: Guid::null(),
            message_type: "ua-data".into(),
            publisher_id: None,
            data_set_class_id: None,
            messages: Vec::new()
        }
    }
}
