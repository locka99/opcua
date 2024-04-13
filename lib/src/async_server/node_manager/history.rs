use std::any::Any;

use crate::{
    async_server::session::continuation_points::ContinuationPoint,
    server::prelude::{
        BinaryEncoder, ExtensionObject, HistoryData, HistoryEvent, HistoryModifiedData,
        HistoryReadValueId, NodeId, ObjectId, QualifiedName, StatusCode, UAString,
    },
};

pub struct HistoryNode {
    node_id: NodeId,
    index_range: UAString,
    data_encoding: QualifiedName,
    input_continuation_point: Option<ContinuationPoint>,
    next_continuation_point: Option<ContinuationPoint>,
    result: Option<ExtensionObject>,
    status: StatusCode,
}

pub trait HistoryResult: BinaryEncoder<Self> + Sized {
    const OBJECT_ID: ObjectId;
    fn as_extension_object(&self) -> ExtensionObject {
        ExtensionObject::from_encodable(Self::OBJECT_ID, self)
    }
}

impl HistoryResult for HistoryData {
    const OBJECT_ID: ObjectId = ObjectId::HistoryData_Encoding_DefaultBinary;
}
impl HistoryResult for HistoryModifiedData {
    const OBJECT_ID: ObjectId = ObjectId::HistoryModifiedData_Encoding_DefaultBinary;
}
impl HistoryResult for HistoryEvent {
    const OBJECT_ID: ObjectId = ObjectId::HistoryEvent_Encoding_DefaultBinary;
}
// impl HistoryResult for HistoryModifiedEvent {}

impl HistoryNode {
    pub(crate) fn new(node: HistoryReadValueId, cp: Option<ContinuationPoint>) -> Self {
        Self {
            node_id: node.node_id,
            index_range: node.index_range,
            data_encoding: node.data_encoding,
            input_continuation_point: cp,
            next_continuation_point: None,
            result: None,
            status: StatusCode::BadNodeIdUnknown,
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn index_range(&self) -> &UAString {
        &self.index_range
    }

    pub fn data_encoding(&self) -> &QualifiedName {
        &self.data_encoding
    }

    pub fn continuation_point(&self) -> Option<&ContinuationPoint> {
        self.input_continuation_point.as_ref()
    }

    pub fn next_continuation_point(&self) -> Option<&ContinuationPoint> {
        self.next_continuation_point.as_ref()
    }

    pub fn set_next_continuation_point(&mut self, continuation_point: Option<ContinuationPoint>) {
        self.next_continuation_point = continuation_point;
    }

    pub fn set_result<T: HistoryResult>(&mut self, result: &T) {
        self.result = Some(result.as_extension_object());
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }
}
