use crate::{
    crypto::random,
    server::session::{continuation_points::ContinuationPoint, instance::Session},
    types::{
        BinaryEncoder, ByteString, DecodingOptions, DeleteAtTimeDetails, DeleteEventDetails,
        DeleteRawModifiedDetails, ExtensionObject, HistoryData, HistoryEvent, HistoryModifiedData,
        HistoryReadResult, HistoryReadValueId, HistoryUpdateResult, NodeId, ObjectId,
        QualifiedName, ReadAnnotationDataDetails, ReadAtTimeDetails, ReadEventDetails,
        ReadProcessedDetails, ReadRawModifiedDetails, StatusCode, UAString, UpdateDataDetails,
        UpdateEventDetails, UpdateStructureDataDetails,
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

pub(crate) enum HistoryReadDetails {
    RawModified(ReadRawModifiedDetails),
    AtTime(ReadAtTimeDetails),
    Processed(ReadProcessedDetails),
    Events(ReadEventDetails),
    Annotations(ReadAnnotationDataDetails),
}

impl HistoryReadDetails {
    pub fn from_extension_object(
        obj: ExtensionObject,
        decoding_options: &DecodingOptions,
    ) -> Result<Self, StatusCode> {
        let object_id = obj
            .object_id()
            .map_err(|_| StatusCode::BadHistoryOperationInvalid)?;
        match object_id {
            ObjectId::ReadRawModifiedDetails_Encoding_DefaultBinary => {
                Ok(Self::RawModified(obj.decode_inner(decoding_options)?))
            }
            ObjectId::ReadAtTimeDetails_Encoding_DefaultBinary => {
                Ok(Self::AtTime(obj.decode_inner(decoding_options)?))
            }
            ObjectId::ReadProcessedDetails_Encoding_DefaultBinary => {
                Ok(Self::Processed(obj.decode_inner(decoding_options)?))
            }
            ObjectId::ReadEventDetails_Encoding_DefaultBinary => {
                Ok(Self::Events(obj.decode_inner(decoding_options)?))
            }
            ObjectId::ReadAnnotationDataDetails_Encoding_DefaultBinary => {
                Ok(Self::Annotations(obj.decode_inner(decoding_options)?))
            }
            _ => Err(StatusCode::BadHistoryOperationInvalid),
        }
    }
}

pub enum HistoryUpdateDetails {
    UpdateData(UpdateDataDetails),
    UpdateStructureData(UpdateStructureDataDetails),
    UpdateEvent(UpdateEventDetails),
    DeleteRawModified(DeleteRawModifiedDetails),
    DeleteAtTime(DeleteAtTimeDetails),
    DeleteEvent(DeleteEventDetails),
}

impl HistoryUpdateDetails {
    pub fn from_extension_object(
        obj: ExtensionObject,
        decoding_options: &DecodingOptions,
    ) -> Result<Self, StatusCode> {
        let object_id = obj
            .object_id()
            .map_err(|_| StatusCode::BadHistoryOperationInvalid)?;
        match object_id {
            ObjectId::UpdateDataDetails_Encoding_DefaultBinary => {
                Ok(Self::UpdateData(obj.decode_inner(decoding_options)?))
            }
            ObjectId::UpdateStructureDataDetails_Encoding_DefaultBinary => Ok(
                Self::UpdateStructureData(obj.decode_inner(decoding_options)?),
            ),
            ObjectId::UpdateEventDetails_Encoding_DefaultBinary => {
                Ok(Self::UpdateEvent(obj.decode_inner(decoding_options)?))
            }
            ObjectId::DeleteRawModifiedDetails_Encoding_DefaultBinary => {
                Ok(Self::DeleteRawModified(obj.decode_inner(decoding_options)?))
            }
            ObjectId::DeleteAtTimeDetails_Encoding_DefaultBinary => {
                Ok(Self::DeleteAtTime(obj.decode_inner(decoding_options)?))
            }
            ObjectId::DeleteEventDetails_Encoding_DefaultBinary => {
                Ok(Self::DeleteEvent(obj.decode_inner(decoding_options)?))
            }
            _ => Err(StatusCode::BadHistoryOperationInvalid),
        }
    }

    pub fn node_id(&self) -> &NodeId {
        match self {
            HistoryUpdateDetails::UpdateData(d) => &d.node_id,
            HistoryUpdateDetails::UpdateStructureData(d) => &d.node_id,
            HistoryUpdateDetails::UpdateEvent(d) => &d.node_id,
            HistoryUpdateDetails::DeleteRawModified(d) => &d.node_id,
            HistoryUpdateDetails::DeleteAtTime(d) => &d.node_id,
            HistoryUpdateDetails::DeleteEvent(d) => &d.node_id,
        }
    }
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

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn into_result(mut self, session: &mut Session) -> HistoryReadResult {
        let cp = match self.next_continuation_point {
            Some(p) => {
                let id = random::byte_string(6);
                if session.add_history_continuation_point(&id, p).is_err() {
                    self.status = StatusCode::BadNoContinuationPoints;
                    ByteString::null()
                } else {
                    id
                }
            }
            None => ByteString::null(),
        };

        HistoryReadResult {
            status_code: self.status,
            continuation_point: cp,
            history_data: self.result.unwrap_or_else(|| ExtensionObject::null()),
        }
    }
}

pub struct HistoryUpdateNode {
    details: HistoryUpdateDetails,
    status: StatusCode,
    operation_results: Option<Vec<StatusCode>>,
}

impl HistoryUpdateNode {
    pub fn new(details: HistoryUpdateDetails) -> Self {
        Self {
            details,
            status: StatusCode::BadNodeIdUnknown,
            operation_results: None,
        }
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn set_operation_results(&mut self, operation_results: Option<Vec<StatusCode>>) {
        self.operation_results = operation_results;
    }

    pub fn into_result(self) -> HistoryUpdateResult {
        HistoryUpdateResult {
            diagnostic_infos: None,
            status_code: self.status,
            operation_results: self.operation_results,
        }
    }

    pub fn details(&self) -> &HistoryUpdateDetails {
        &self.details
    }
}
