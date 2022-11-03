use std::collections::HashMap;

use crate::types::*;

/// Optional fields are determined by DataSetMessageContentMask
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DataSetMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    data_set_writer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    data_set_writer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    sequence_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    meta_data_version: Option<ConfigurationVersionDataType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    timestamp: Option<DateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    status: Option<StatusCode>,
    /// Possible values "ua-keyframe", "ua-deltaframe", "ua-event", "ua-keepalive"
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    message_type: Option<String>,
    payload: HashMap<String, Variant>,
}

impl DataSetMessage {}
