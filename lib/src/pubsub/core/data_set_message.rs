use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use serde_json::json;

use crate::types::*;

use super::{deserialize_status_code_option, message_type};

/// Optional fields are determined by DataSetMessageContentMask
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct DataSetMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub data_set_writer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub data_set_writer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub sequence_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub meta_data_version: Option<ConfigurationVersionDataType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub timestamp: Option<DateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_status_code_option")]
    pub status: Option<StatusCode>,
    /// Possible values "ua-keyframe", "ua-deltaframe", "ua-event", "ua-keepalive"
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub message_type: Option<String>,
    pub payload: HashMap<String, Variant>,
}

impl DataSetMessage {
    pub fn keyframe(payload: HashMap<String, Variant>) -> Self {
        Self {
            message_type: Some(message_type::KEYFRAME.into()),
            payload,
            ..Default::default()
        }
    }

    pub fn keepalive() -> Self {
        Self {
            message_type: Some(message_type::KEEPALIVE.into()),
            ..Default::default()
        }
    }
}

#[test]
fn serialize() {
    let msg1 = DataSetMessage {
        data_set_writer_id: Some("Writer_Id_1".into()),
        data_set_writer_name: Some("Writer_Name_1".into()),
        sequence_number: Some(1234),
        meta_data_version: Some(ConfigurationVersionDataType {
            major_version: 1001,
            minor_version: 2002,
        }),
        timestamp: Some(DateTime::now()),
        status: Some(StatusCode::BadViewIdUnknown),
        message_type: Some(message_type::KEYFRAME.into()),
        payload: HashMap::new(),
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
    assert!(v.contains(message_type::KEYFRAME));

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
    assert!(v.data_set_writer_id.is_none());
    assert!(v.data_set_writer_name.is_none());
    assert!(v.meta_data_version.is_none());
    assert!(v.timestamp.is_none());
    assert!(v.status.is_none());
    assert!(v.message_type.is_none());
}
