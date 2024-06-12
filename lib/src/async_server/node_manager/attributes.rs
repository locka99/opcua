use crate::server::prelude::{DataValue, DateTime, ReadValueId, StatusCode, WriteValue};

pub struct ReadNode {
    node: ReadValueId,
    pub(crate) result: DataValue,
}

impl ReadNode {
    pub fn new(node: ReadValueId) -> Self {
        Self {
            node,
            result: DataValue {
                status: Some(StatusCode::BadNodeIdUnknown),
                server_timestamp: Some(DateTime::now()),
                ..Default::default()
            },
        }
    }

    pub fn node(&self) -> &ReadValueId {
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

pub struct WriteNode {
    value: WriteValue,
    status: StatusCode,
}

impl WriteNode {
    pub fn new(value: WriteValue) -> Self {
        Self {
            value,
            status: StatusCode::BadNodeIdUnknown,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    pub fn value(&self) -> &WriteValue {
        &self.value
    }
}
