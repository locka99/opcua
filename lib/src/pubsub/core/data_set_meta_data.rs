use crate::prelude::{
    ConfigurationVersionDataType, DataSetMetaDataType, Guid, LocalizedText, UAString,
};

use super::message_type::METADATA;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DataSetMetaData {
    /// A globally unique identifier for the message
    pub message_id: String,
    /// A value that is "ua-metadata"
    pub message_type: String,
    /// A unique identifier for the publisher. It identifies the source of the message.
    pub publisher_id: String,
    /// An identifier for DataSetWriter which published the DataSetMetaData
    pub data_set_writer_id: u16,
    /// The meta data as defined in 6.2.2.1.2
    pub meta_data: DataSetMetaDataType,
}

impl Default for DataSetMetaData {
    fn default() -> Self {
        Self {
            message_id: String::new(),
            message_type: METADATA.into(),
            publisher_id: String::new(),
            data_set_writer_id: 0,
            meta_data: DataSetMetaDataType {
                namespaces: None,
                structure_data_types: None,
                enum_data_types: None,
                simple_data_types: None,
                name: UAString::default(),
                description: LocalizedText::default(),
                fields: None,
                data_set_class_id: Guid::default(),
                configuration_version: ConfigurationVersionDataType {
                    major_version: 0,
                    minor_version: 0,
                },
            },
        }
    }
}
