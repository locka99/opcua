// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use std::sync::Arc;

use crate::client::prelude::StatusCode;
use crate::types::*;

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

struct PublishedDataItems {
    last_configuration_version: ConfigurationVersionDataType,
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
        configuration_version: ConfigurationVersionDataType,
        aliases: &[&str],
        promoted_fields: &[bool],
        variables: &[PublishedVariableDataType],
        max_published_variables: usize,
    ) -> Result<(ConfigurationVersionDataType, Vec<StatusCode>), StatusCode> {
        if configuration_version != self.last_configuration_version {
            Err(StatusCode::BadInvalidState)
        } else if aliases.len() != promoted_fields.len() || aliases.len() != variables.len() {
            Err(StatusCode::BadInvalidArgument)
        } else if aliases.is_empty() {
            Err(StatusCode::BadNothingToDo)
        } else {
            self.last_configuration_version = configuration_version;
            let result = aliases
                .iter()
                .enumerate()
                .map(|v| {
                    let idx = v.0;
                    let alias = *v.1;
                    if self.variables.len() >= max_published_variables {
                        StatusCode::BadUnexpectedError // BadTooManyVariables
                    } else {
                        let promoted = promoted_fields[idx];
                        let variable = variables[idx].clone();
                        // TODO NodeIdInvalid
                        // TODO NodeIdUnknown
                        // TODO IndexRangeInvalid
                        // TODO IndexRangeNoData
                        self.variables.push((alias.to_string(), promoted, variable));
                        StatusCode::Good
                    }
                })
                .collect();
            Ok((self.last_configuration_version.clone(), result))
        }
    }

    // TODO remove variables
    pub fn remove_variables(&mut self) {}
}
