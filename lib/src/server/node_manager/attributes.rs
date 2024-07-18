use crate::types::{
    AttributeId, DataValue, DateTime, NodeId, NumericRange, QualifiedName, ReadValueId, StatusCode,
    WriteValue,
};

#[derive(Debug, Clone)]
/// Parsed and validated version of a raw ReadValueId from OPC-UA.
pub struct ParsedReadValueId {
    pub node_id: NodeId,
    pub attribute_id: AttributeId,
    pub index_range: NumericRange,
    pub data_encoding: QualifiedName,
}

impl ParsedReadValueId {
    /// Try to parse from a `ReadValueId`.
    pub fn parse(val: ReadValueId) -> Result<Self, StatusCode> {
        let attribute_id = AttributeId::from_u32(val.attribute_id)
            .map_err(|_| StatusCode::BadAttributeIdInvalid)?;
        let index_range: NumericRange = val
            .index_range
            .as_ref()
            .parse()
            .map_err(|_| StatusCode::BadIndexRangeInvalid)?;

        Ok(Self {
            node_id: val.node_id,
            attribute_id,
            index_range,
            // TODO: Do something here? Do we actually care about supporting custom data encodings?
            data_encoding: val.data_encoding,
        })
    }

    /// Create a "null" `ParsedReadValueId`, with no node ID.
    pub fn null() -> Self {
        Self {
            node_id: NodeId::null(),
            attribute_id: AttributeId::NodeId,
            index_range: NumericRange::None,
            data_encoding: QualifiedName::null(),
        }
    }

    /// Check whether this `ParsedReadValueId` is null.
    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}

impl Default for ParsedReadValueId {
    fn default() -> Self {
        Self::null()
    }
}

#[derive(Debug)]
/// Container for a single item in a `Read` service call.
pub struct ReadNode {
    node: ParsedReadValueId,
    pub(crate) result: DataValue,
}

impl ReadNode {
    /// Create a `ReadNode` from a `ReadValueId`.
    pub(crate) fn new(node: ReadValueId) -> Self {
        let mut status = StatusCode::BadNodeIdUnknown;

        let node = match ParsedReadValueId::parse(node) {
            Ok(r) => r,
            Err(e) => {
                status = e;
                ParsedReadValueId::null()
            }
        };

        Self {
            node,
            result: DataValue {
                status: Some(status),
                server_timestamp: Some(DateTime::now()),
                ..Default::default()
            },
        }
    }

    /// Get the current result status code.
    pub fn status(&self) -> StatusCode {
        self.result.status()
    }

    /// Get the node/attribute pair to read.
    pub fn node(&self) -> &ParsedReadValueId {
        &self.node
    }

    /// Set the result of this read operation.
    pub fn set_result(&mut self, result: DataValue) {
        self.result = result;
    }

    /// Set the result of this read operation to an error with no value or
    /// timestamp. Use this not if the value is an error, but if the read
    /// failed.
    pub fn set_error(&mut self, status: StatusCode) {
        self.result = DataValue {
            status: Some(status),
            server_timestamp: Some(DateTime::now()),
            ..Default::default()
        }
    }

    pub(crate) fn take_result(self) -> DataValue {
        self.result
    }
}

#[derive(Debug, Clone)]
/// Parsed and validated version of the raw OPC-UA `WriteValue`.
pub struct ParsedWriteValue {
    pub node_id: NodeId,
    pub attribute_id: AttributeId,
    pub index_range: NumericRange,
    pub value: DataValue,
}

impl ParsedWriteValue {
    /// Try to parse from a `WriteValue`.
    pub fn parse(val: WriteValue) -> Result<Self, StatusCode> {
        let attribute_id = AttributeId::from_u32(val.attribute_id)
            .map_err(|_| StatusCode::BadAttributeIdInvalid)?;
        let index_range: NumericRange = val
            .index_range
            .as_ref()
            .parse()
            .map_err(|_| StatusCode::BadIndexRangeInvalid)?;

        Ok(Self {
            node_id: val.node_id,
            attribute_id,
            index_range,
            value: val.value,
        })
    }

    /// Create a "null" `ParsedWriteValue`.
    pub fn null() -> Self {
        Self {
            node_id: NodeId::null(),
            attribute_id: AttributeId::NodeId,
            index_range: NumericRange::None,
            value: DataValue::null(),
        }
    }

    /// Check if this `ParsedWriteValue` is null.
    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}

impl Default for ParsedWriteValue {
    fn default() -> Self {
        Self::null()
    }
}

/// Container for a single item in a `Write` service call.
#[derive(Debug)]
pub struct WriteNode {
    value: ParsedWriteValue,
    status: StatusCode,
}

impl WriteNode {
    /// Create a `WriteNode` from a raw OPC-UA `WriteValue`.
    pub(crate) fn new(value: WriteValue) -> Self {
        let mut status = StatusCode::BadNodeIdUnknown;

        let value = match ParsedWriteValue::parse(value) {
            Ok(r) => r,
            Err(e) => {
                status = e;
                ParsedWriteValue::null()
            }
        };

        Self { value, status }
    }

    /// Get the current status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Set the status code result of this operation.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Get the value to write.
    pub fn value(&self) -> &ParsedWriteValue {
        &self.value
    }
}
