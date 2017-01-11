use std::io::{Read, Write, Seek, Result};

use super::encodable_types::*;
use super::date_time::*;
use super::variant::*;
use super::status_codes::*;

/// Data type ID 23
#[derive(PartialEq, Debug, Clone)]
pub struct DataValue {
    pub value: Box<Variant>,
    pub status: StatusCode,
    pub source_timestamp: DateTime,
    pub source_pico_seconds: Int16,
    pub server_timestamp: DateTime,
    pub server_pico_seconds: Int16,
}

impl BinaryEncoder<DataValue> for DataValue {
    fn byte_len(&self) -> usize {
        unimplemented!();
    }

    fn encode<S: Write + Seek>(&self, stream: &mut S) -> Result<usize> {
        // This impl should be overridden
        unimplemented!()
    }

    fn decode<S: Read + Seek>(_: &mut S) -> Result<DataValue> {
        // This impl should be overridden
        unimplemented!()
    }
}
