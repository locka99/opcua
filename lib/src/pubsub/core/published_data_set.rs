use std::sync::Arc;

use crate::client::prelude::StatusCode;

use super::DataSetWriter;

pub struct PublishedDataSet {
    // 0 or more writers are associated with the dataset
    pub writers: Vec<Arc<Box<dyn DataSetWriter>>>,
}

impl Default for PublishedDataSet {
    fn default() -> Self {
        Self {
            writers: Vec::new(),
        }
    }
}

impl PublishedDataSet {
    pub fn add_writer(&mut self, writer: Arc<Box<dyn DataSetWriter>>) {
        self.writers.push(writer);
    }
}

const MAX_PUBLISHED_VARIABLES: usize = 10;

struct PublishedDataItems {
    last_configuration_version: ConfigurationVersion,
    // TODO ConfigurationVersionDataType

    // TODO PublishedDataSetDataType

    // TODO PublishedDataSetSourceDataType
    variables: Vec<(String, bool, PublishedVariableDataType)>,
}

impl PublishedDataItems {
    /// This function is internally equivalent to AddVariables in the address space so takes
    /// similar arguments and yields similar responses.
    pub fn add_variables(
        &mut self,
        configuration_version: ConfigurationVersion,
        aliases: &[&str],
        promoted_fields: &[bool],
        variables: &[PublishedVariableDataType],
    ) -> Result<(ConfigurationVersion, Vec<StatusCode>), StatusCode> {
        if configuration_version != self.last_configuration_version {
            Err(StatusCode::BadInvalidState)
        } else if aliases.len() != promoted_fields.len() || aliases.len() != variables.len() {
            Err(StatusCode::BadInvalidArgument)
        } else if aliases.is_empty() {
            Err(StatusCode::BadNothingToDo)
        } else {
            self.last_configuration_version = configuration_version;
            let result= aliases
                .iter()
                .zip(promoted_fields.iter())
                .zip(variables.iter())
                .map(|v| {
                if self.variables.len() >= MAX_PUBLISHED_VARIABLES {
                    StatusCode::BadUnexpectedError // BadTooManyVariables
                } else {
                    // TODO NodeIdInvalid
                    // TODO NodeIdUnknown
                    // TODO IndexRangeInvalid
                    // TODO IndexRangeNoData
                    self.variables.push(v);
                    StatusCode::Good
                }
            }).collect();
            Ok((self.last_configuration_version.clone(), results))
        }
    }

    // TODO remove variables
    pub fn remove_variables(&mut self) {}
}
