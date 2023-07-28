use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[cfg(test)]
use serde_json::json;

use crate::types::*;

use crate::pubsub::core::{self};

use super::deserialize_status_code_option;

/// This represents the payload of the DataSetMessage. It can be ad hoc JSON, or it can be a serialized DataValue
/// or Variant.
#[derive(Debug, PartialEq)]
pub enum Payload {
    /// If the DataSetFieldContentMask results in a RawData representation, the field value is
    /// a Variant encoded using the non-reversible OPC UA JSON Data Encoding defined in
    /// OPC 10000-6.
    RawValue(Value),
    /// If the DataSetFieldContentMask results in a DataValue representation, the field value is
    /// a DataValue encoded using the non-reversible OPC UA JSON Data Encoding defined
    /// in OPC 10000-6.
    DataValue(DataValue, DataSetFieldContentMask),
    /// If the DataSetFieldContentMask results in a Variant representation, the field value is
    /// encoded as a Variant encoded using the reversible OPC UA JSON Data Encoding
    /// defined in OPC 10000-6.
    Variant(Variant),
}

impl Default for Payload {
    fn default() -> Self {
        Payload::RawValue(Value::Null)
    }
}

impl Serialize for Payload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Payload::RawValue(value) => value.serialize(serializer),
            Payload::DataValue(value, _message_type) => {
                // TODO serializing flags from _message_type
                value.serialize(serializer)
            }
            Payload::Variant(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Payload {
    fn deserialize<D>(deserializer: D) -> Result<Payload, D::Error>
    where
        D: Deserializer<'de>,
    {
        unimplemented!()
    }
}

/// JSON DataSetMessage definition.
///
/// Optional fields are determined by DataSetMessageContentMask
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct DataSetMessage {
    /// An identifier for the dataset writer which created the DataSetMessage. This value is unique
    /// within the scope of the publisher.
    pub data_set_writer_id: String,
    /// Strictly monotonically increasing sequence number assigned to the DataSetMessage by the data set writer.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub sequence_number: Option<u32>,
    /// The version of the data set meta data which describes the contents of the payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub meta_data_version: Option<ConfigurationVersionDataType>,
    /// A timestamp which applies to all values contained in the DataSetMessage
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub timestamp: Option<DateTime>,
    /// A status code which applies to all values contained in the DataSetMessage
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_status_code_option")]
    pub status: Option<StatusCode>,
    /// A JSON object containing the name value pairs specified by the published data set. The format
    /// of the value depends on the data type of the field and the flags specified
    /// by the DataSetMessage content mask.
    pub payload: Payload,
}

impl core::DataSetMessage for DataSetMessage {}

impl DataSetMessage {
    pub fn new(data_set_writer_id: String, payload: Payload) -> Self {
        Self {
            data_set_writer_id,
            payload,
            ..Default::default()
        }
    }
}

#[test]
fn serialize() {
    let msg1 = DataSetMessage {
        data_set_writer_id: "Writer_Id_1".into(),
        sequence_number: Some(1234),
        meta_data_version: Some(ConfigurationVersionDataType {
            major_version: 1001,
            minor_version: 2002,
        }),
        timestamp: Some(DateTime::rfc3339_now()),
        status: Some(StatusCode::BadViewIdUnknown),
        payload: Payload::RawValue(Value::Null),
    };

    // Serialize, deserialize, compare to original
    let v = serde_json::to_string(&msg1).unwrap();

    let now = DateTime::now();
    let now_str = now.to_string();

    println!("JSON from serializing == {}", v);

    // Test for field/value expected / unexpected
    assert!(v.contains("DataSetWriterId"));
    assert!(v.contains("Writer_Id_1"));

    assert!(v.contains("DataSetWriterName"));
    assert!(v.contains("Writer_Name_1"));

    assert!(v.contains("SequenceNumber"));
    assert!(v.contains("1234"));

    assert!(v.contains("Timestamp"));
    // TODO expected time format assert!(v.contains(now_str));

    assert!(v.contains("MetaDataVersion"));
    assert!(v.contains("MajorVersion"));
    assert!(v.contains("1001"));
    assert!(v.contains("MinorVersion"));
    assert!(v.contains("2002"));

    assert!(v.contains("Status"));
    assert!(v.contains("2154496000")); // Hex 0x806B_0000 as decimal

    assert!(v.contains("MessageType"));

    assert!(v.contains("Payload"));

    let msg2 = serde_json::from_str(&v).unwrap();

    assert_eq!(msg1, msg2)
}

#[test]
fn deserialize() {
    // Deserialze some json, expect Optional fields results to match

    // An empty message
    let in1 = json!({
        "Payload": {}
    });
    let v: DataSetMessage = serde_json::from_value(in1).unwrap();
    assert!(v.data_set_writer_id.is_empty());
    assert!(v.meta_data_version.is_none());
    assert!(v.timestamp.is_none());
    assert!(v.status.is_none());
}
