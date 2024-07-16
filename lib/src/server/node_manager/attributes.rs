use crate::types::{
    AttributeId, DataValue, DateTime, NodeId, NumericRange, QualifiedName, ReadValueId, StatusCode,
    WriteValue,
};

#[derive(Debug, Clone)]
pub struct ParsedReadValueId {
    pub node_id: NodeId,
    pub attribute_id: AttributeId,
    pub index_range: NumericRange,
    pub data_encoding: QualifiedName,
}

impl ParsedReadValueId {
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

    pub fn null() -> Self {
        Self {
            node_id: NodeId::null(),
            attribute_id: AttributeId::NodeId,
            index_range: NumericRange::None,
            data_encoding: QualifiedName::null(),
        }
    }

    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}

pub struct ReadNode {
    node: ParsedReadValueId,
    pub(crate) result: DataValue,
}

impl ReadNode {
    pub fn new(node: ReadValueId) -> Self {
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

    pub fn status(&self) -> StatusCode {
        self.result.status()
    }

    pub fn node(&self) -> &ParsedReadValueId {
        &self.node
    }

    pub fn set_result(&mut self, result: DataValue) {
        self.result = result;
    }

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
pub struct ParsedWriteValue {
    pub node_id: NodeId,
    pub attribute_id: AttributeId,
    pub index_range: NumericRange,
    pub value: DataValue,
}

impl ParsedWriteValue {
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

    pub fn null() -> Self {
        Self {
            node_id: NodeId::null(),
            attribute_id: AttributeId::NodeId,
            index_range: NumericRange::None,
            value: DataValue::null(),
        }
    }

    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}

pub struct WriteNode {
    value: ParsedWriteValue,
    status: StatusCode,
}

impl WriteNode {
    pub fn new(value: WriteValue) -> Self {
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

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    pub fn value(&self) -> &ParsedWriteValue {
        &self.value
    }
}
