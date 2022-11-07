use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use crate::types::*;

use super::MessageType;

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
    pub status: Option<StatusCode>,
    /// Possible values "ua-keyframe", "ua-deltaframe", "ua-event", "ua-keepalive"
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub message_type: Option<String>,
    pub payload: HashMap<String, Variant>,
}

#[test]
fn serialize() {
    let msg1 = DataSetMessage {
        data_set_writer_id: Some("Writer_Id_1".into()),
        data_set_writer_name: Some("Writer_Name_1".into()),
        sequence_number: Some(1234),
        meta_data_version: None,
        timestamp: Some(DateTime::now()),
        status: Some(StatusCode::BadViewIdUnknown),
        message_type: Some(MessageType::KEYFRAME.into()),
        payload: HashMap::new()
    };

    // Serialize, deserialize, compare to original
    let v = serde_json::to_string(&msg1).unwrap();

    let now = DateTime::now();
    let now_str = now.to_string();

    // Test for field/value expected / unexpected
    assert!(v.contains("DataSetWriterId"));
    assert!(v.contains("Writer_Id_1"));

    assert!(v.contains("DataSetWriterName"));
    assert!(v.contains("Writer_Name_1"));

    assert!(v.contains("SequenceNumber"));
    assert!(v.contains("1234"));

    assert!(v.contains("DateTime"));
    // TODO expected time format assert!(v.contains(now_str));

    assert!(!v.contains("MetaDataVersion"));

    assert!(v.contains("StatusCode"));
    assert!(v.contains("2154496000")); // Hex 0x806B_0000 as decimal

    assert!(v.contains("MessageType"));
    assert!(v.contains(MessageType::KEYFRAME));

    assert!(v.contains("Payload"));

    let msg2 = serde_json::from_str(&v).unwrap();

    assert_eq!(msg1, msg2)
}

#[test]
fn deserialize() {
    // Deserialze some json, expect Optional fields results to match
}