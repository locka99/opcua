use crate::prelude::{
    ConfigurationVersionDataType, DataSetMetaDataType, Guid, LocalizedText, UAString,
};

use super::message_type::METADATA;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DataSetMetaData {
    pub message_id: String,
    pub message_type: String,
    pub publisher_id: String,
    pub data_set_writer_id: u16,
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
