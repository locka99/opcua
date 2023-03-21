use crate::types::*;

use crate::pubsub::core::{self, DataSetMessage};
use super::*;

/// The JSON NetworkMessage is a container for DataSetMessages and includes information shared 
/// between DataSetMessages.
///
// Optional fields are provided during construction, or by NetworkMessageContentMask
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkMessage {
    /// A globally unique identifier for the message, e.g. a guid. Converted to a string for JSON.
    #[serde(deserialize_with = "deserialize_from_str")]
    #[serde(serialize_with = "serialize_to_str")]
    message_id: Guid,
    /// Message type value is always "ua-data"
    message_type: String,
    /// Publisher id which is a u32 converted to a string for JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_from_str_option")]
    //#[serde(serialize_with = "serialize_to_str")]
    publisher_id: Option<u32>,
    /// Dataset class id associated with the datasets in the network message. A guid converted to a string for JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_from_str_option")]
    //#[serde(serialize_with = "serialize_to_str")]
    data_set_class_id: Option<Guid>,
    /// An array of DataSetMessages. Can also be serialized as an object in JSON if SingleDataSetMessage bit is set
    messages: Vec<dyn DataSetMessage>,
}

impl Default for NetworkMessage {
    fn default() -> Self {
        Self {
            message_id: Guid::null(),
            message_type: message_type::DATA.into(),
            publisher_id: None,
            data_set_class_id: None,
            messages: Vec::new(),
        }
    }
}

impl core::NetworkMessage for NetworkMessage {}

impl NetworkMessage {
    fn new_data(publisher_id: u32, data_set_class_id: Some<Guid>, payload: Vec<dyn DataSetMessage>) -> Self {
        Self {
            message_id: Guid::new(),
            message_type: message_type::DATA.into(),
            publisher_id: Some(publisher_id),
            data_set_class_id,
            messages,
        }
    }
}
