use crate::types::*;

use super::*;

#[derive(Clone)]
pub struct DataSetField {
    /// Alias for the variable
    alias: String,
    /// Value
    value: DataValue,
    /// Flag inidicating if the field is promoted to the DataSetMessageHeader
    promoted: bool,
}

impl DataSetField {}

pub struct DataSet {
    meta_data: DataSetMetaData,
    values: Vec<DataSetField>,
}

impl DataSet {
    pub fn new(meta_data: DataSetMetaData) -> DataSet {
        Self {
            meta_data,
            values: Vec::new(),
        }
    }

    pub fn add_variables(&mut self, values: &[DataSetField]) {
        self.values.extend_from_slice(values);
    }

    pub fn meta_data(&self) -> &DataSetMetaData {
        &self.meta_data
    }

    pub fn values(&self) -> &Vec<DataSetField> {
        &self.values
    }
}
