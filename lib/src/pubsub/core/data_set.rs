use crate::types::*;

use super::*;

pub struct DataSetMessageField {
    value: DataValue
}

pub struct DataSet {
    pub flags: DataSetFieldFlags,
    pub meta_data: DataSetMetaData,
    pub fields: Vec<DataSetMessageField>
}
