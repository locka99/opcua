use crate::{
    crypto::random,
    server::session::{continuation_points::ContinuationPoint, instance::Session},
    types::{
        BinaryEncoder, ByteString, DecodingOptions, DeleteAtTimeDetails, DeleteEventDetails,
        DeleteRawModifiedDetails, ExtensionObject, HistoryData, HistoryEvent, HistoryModifiedData,
        HistoryReadResult, HistoryReadValueId, HistoryUpdateResult, NodeId, NumericRange, ObjectId,
        QualifiedName, ReadAnnotationDataDetails, ReadAtTimeDetails, ReadEventDetails,
        ReadProcessedDetails, ReadRawModifiedDetails, StatusCode, UpdateDataDetails,
        UpdateEventDetails, UpdateStructureDataDetails,
    },
};

/// Container for a single node in a history read request.
pub struct HistoryNode {
    node_id: NodeId,
    index_range: NumericRange,
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

/// Details object for history updates.
#[derive(Debug, Clone)]
pub enum HistoryUpdateDetails {
    UpdateData(UpdateDataDetails),
    UpdateStructureData(UpdateStructureDataDetails),
    UpdateEvent(UpdateEventDetails),
    DeleteRawModified(DeleteRawModifiedDetails),
    DeleteAtTime(DeleteAtTimeDetails),
    DeleteEvent(DeleteEventDetails),
}

impl HistoryUpdateDetails {
    /// Try to create a `HistoryUpdateDetails` object from an extension object.
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

    /// Get the node ID of the details object, independent of type.
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

/// Trait for values storable as history data.
pub trait HistoryResult: BinaryEncoder<Self> + Sized {
    /// The object ID of the object encoding.
    const OBJECT_ID: ObjectId;

    /// Return an extension object containing the encoded data for the current object.
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
    pub(crate) fn new(
        node: HistoryReadValueId,
        is_events: bool,
        cp: Option<ContinuationPoint>,
    ) -> Self {
        let mut status = StatusCode::BadNodeIdUnknown;
        let index_range = match node.index_range.as_ref().parse::<NumericRange>() {
            Err(_) => {
                status = StatusCode::BadIndexRangeInvalid;
                NumericRange::None
            }
            Ok(r) => r,
        };

        if !matches!(index_range, NumericRange::None) && is_events {
            status = StatusCode::BadIndexRangeDataMismatch;
        }

        Self {
            node_id: node.node_id,
            index_range,
            data_encoding: node.data_encoding,
            input_continuation_point: cp,
            next_continuation_point: None,
            result: None,
            status,
        }
    }

    /// Get the node ID to read history from.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get the index range to read.
    pub fn index_range(&self) -> &NumericRange {
        &self.index_range
    }

    /// Get the specified data encoding to read.
    pub fn data_encoding(&self) -> &QualifiedName {
        &self.data_encoding
    }

    /// Get the current continuation point.
    pub fn continuation_point(&self) -> Option<&ContinuationPoint> {
        self.input_continuation_point.as_ref()
    }

    /// Get the next continuation point.
    pub fn next_continuation_point(&self) -> Option<&ContinuationPoint> {
        self.next_continuation_point.as_ref()
    }

    /// Set the next continuation point.
    pub fn set_next_continuation_point(&mut self, continuation_point: Option<ContinuationPoint>) {
        self.next_continuation_point = continuation_point;
    }

    /// Set the result to some history data object.
    pub fn set_result<T: HistoryResult>(&mut self, result: &T) {
        self.result = Some(result.as_extension_object());
    }

    /// Set the result status.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Get the current result status.
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

/// History update details for one node.
pub struct HistoryUpdateNode {
    details: HistoryUpdateDetails,
    status: StatusCode,
    operation_results: Option<Vec<StatusCode>>,
}

impl HistoryUpdateNode {
    pub(crate) fn new(details: HistoryUpdateDetails) -> Self {
        Self {
            details,
            status: StatusCode::BadNodeIdUnknown,
            operation_results: None,
        }
    }

    /// Set the result status of this history operation.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Get the current status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Set the operation results. If present the length must match
    /// the length of the entries in the history update details.
    pub fn set_operation_results(&mut self, operation_results: Option<Vec<StatusCode>>) {
        self.operation_results = operation_results;
    }

    pub(crate) fn into_result(self) -> HistoryUpdateResult {
        HistoryUpdateResult {
            diagnostic_infos: None,
            status_code: self.status,
            operation_results: self.operation_results,
        }
    }

    /// Get a reference to the history update details describing the history update
    /// to execute.
    pub fn details(&self) -> &HistoryUpdateDetails {
        &self.details
    }
}
