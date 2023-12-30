// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use std::collections::HashMap;
use std::fmt;

use serde::{
    de::{self, MapAccess},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::Value;

#[cfg(test)]
use serde_json::json;

use crate::types::*;

use crate::pubsub::core::{self};

use super::deserialize_status_code_option;

/// This represents the payload of the DataSetMessage. It can be ad hoc JSON, or it can be a serialized DataValue
/// or Variant.
#[derive(Debug, PartialEq)]
pub enum PayloadValue {
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

impl Default for PayloadValue {
    fn default() -> Self {
        PayloadValue::RawValue(Value::Null)
    }
}

impl Serialize for PayloadValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            PayloadValue::RawValue(value) => value.serialize(serializer),
            PayloadValue::DataValue(value, _message_type) => {
                // TODO serializing flags from _message_type
                value.serialize(serializer)
            }
            PayloadValue::Variant(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PayloadValue {
    fn deserialize<D>(deserializer: D) -> Result<PayloadValue, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PayloadVisitor)
    }
}

struct PayloadVisitor;

impl<'de> serde::de::Visitor<'de> for PayloadVisitor {
    type Value = PayloadValue;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a payload value")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(PayloadValue::RawValue(Value::Null))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        // Payload is a map of changes
        let mut map: HashMap<String, String> = HashMap::new();
        while let Ok(Some((key, value))) = access.next_entry() {
            map.insert(key, value);
        }
        Ok(PayloadValue::RawValue(Value::Null))
    }
}

pub type Payload = HashMap<String, PayloadValue>;

/// JSON DataSetMessage definition.
///
/// Optional fields are determined by DataSetMessageContentMask
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct DataSetMessage {
    /// An identifier for the dataset writer which created the DataSetMessage. This value is unique
    /// within the scope of the publisher.
    /// TODO Json mapping for this field is UInt16
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
        payload: Payload::new(),
    };

    // Serialize, deserialize, compare to original
    let v = serde_json::to_string(&msg1).unwrap();

    let now = DateTime::now();
    let now_str = now.to_string();

    println!("JSON from serializing == {}", v);

    // Test for field/value expected / unexpected
    assert!(v.contains("DataSetWriterId"));
    assert!(v.contains("Writer_Id_1"));

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

    assert!(v.contains("Payload"));

    let msg2 = serde_json::from_str(&v).unwrap();

    assert_eq!(msg1, msg2)
}

#[test]
fn deserialize_payloadvalue() {
    let json = json!({
      "Value": 99,
      "SourceTimestamp": "2020-03-24T23:30:55.9891469Z",
      "ServerTimestamp": "2020-03-24T23:30:55.9891469Z"
    });
    let v: PayloadValue = serde_json::from_value(json).unwrap();
}

#[test]
fn deserialize_payload() {
    let json = json!({
         "http://test.org/UA/Data/#i=10845": {
          "Value": 99,
          "SourceTimestamp": "2020-03-24T23:30:55.9891469Z",
          "ServerTimestamp": "2020-03-24T23:30:55.9891469Z"
        },
        "http://test.org/UA/Data/#i=10846": {
          "Value": 251,
          "SourceTimestamp": "2020-03-24T23:30:55.9891469Z",
          "ServerTimestamp": "2020-03-24T23:30:55.9891469Z"
        }
    });

    let v: Payload = serde_json::from_value(json).unwrap();
    assert!(v.contains_key("http://test.org/UA/Data/#i=10845"));
    assert!(v.contains_key("http://test.org/UA/Data/#i=10846"));
}

#[test]
fn deserialize_sample() {
    let json = json!({
      "DataSetWriterId": "uat46f9f8f82fd5c1b42a7de31b5dc2c11ef418a62f",
      "SequenceNumber": 18,
      "MetaDataVersion": {
        "MajorVersion": 1,
        "MinorVersion": 1
      },
      "Timestamp": "2020-03-24T23:30:56.9597112Z",
      "Status": null,
      "Payload": {
        "http://test.org/UA/Data/#i=10845": {
          "Value": 99,
          "SourceTimestamp": "2020-03-24T23:30:55.9891469Z",
          "ServerTimestamp": "2020-03-24T23:30:55.9891469Z"
        },
        "http://test.org/UA/Data/#i=10846": {
          "Value": 251,
          "SourceTimestamp": "2020-03-24T23:30:55.9891469Z",
          "ServerTimestamp": "2020-03-24T23:30:55.9891469Z"
        }
      }
    });

    let v: DataSetMessage = serde_json::from_value(json).unwrap();
}

#[test]
fn deserialize() {
    // Deserialze some json, expect Optional fields results to match

    // An empty message
    let in1 = json!({
        "DataSetWriterId": "",
        "Payload": {}
    });
    let v: DataSetMessage = serde_json::from_value(in1).unwrap();
    assert!(v.data_set_writer_id.is_empty());
    assert!(v.meta_data_version.is_none());
    assert!(v.timestamp.is_none());
    assert!(v.status.is_none());
}
