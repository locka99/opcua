use crate::{
    client::{
        session::{
            process_service_result, process_unexpected_response, session_debug, session_error,
        },
        Session,
    },
    core::supported_message::SupportedMessage,
    types::{
        DataValue, DeleteAtTimeDetails, DeleteEventDetails, DeleteRawModifiedDetails,
        ExtensionObject, HistoryReadRequest, HistoryReadResult, HistoryReadValueId,
        HistoryUpdateRequest, HistoryUpdateResult, ObjectId, ReadAtTimeDetails, ReadEventDetails,
        ReadProcessedDetails, ReadRawModifiedDetails, ReadRequest, ReadValueId, StatusCode,
        TimestampsToReturn, UpdateDataDetails, UpdateEventDetails, UpdateStructureDataDetails,
        WriteRequest, WriteValue,
    },
};

/// Enumeration used with Session::history_read()
pub enum HistoryReadAction {
    Event(ReadEventDetails),
    RawModified(ReadRawModifiedDetails),
    Processed(ReadProcessedDetails),
    ReadAtTime(ReadAtTimeDetails),
}

impl From<HistoryReadAction> for ExtensionObject {
    fn from(action: HistoryReadAction) -> Self {
        match action {
            HistoryReadAction::Event(v) => {
                Self::from_encodable(ObjectId::ReadEventDetails_Encoding_DefaultBinary, &v)
            }
            HistoryReadAction::RawModified(v) => {
                Self::from_encodable(ObjectId::ReadRawModifiedDetails_Encoding_DefaultBinary, &v)
            }
            HistoryReadAction::Processed(v) => {
                Self::from_encodable(ObjectId::ReadProcessedDetails_Encoding_DefaultBinary, &v)
            }
            HistoryReadAction::ReadAtTime(v) => {
                Self::from_encodable(ObjectId::ReadAtTimeDetails_Encoding_DefaultBinary, &v)
            }
        }
    }
}

/// Enumeration used with Session::history_update()
pub enum HistoryUpdateAction {
    UpdateData(UpdateDataDetails),
    UpdateStructureData(UpdateStructureDataDetails),
    UpdateEvent(UpdateEventDetails),
    DeleteRawModified(DeleteRawModifiedDetails),
    DeleteAtTime(DeleteAtTimeDetails),
    DeleteEvent(DeleteEventDetails),
}

impl From<&HistoryUpdateAction> for ExtensionObject {
    fn from(action: &HistoryUpdateAction) -> Self {
        match action {
            HistoryUpdateAction::UpdateData(v) => {
                Self::from_encodable(ObjectId::UpdateDataDetails_Encoding_DefaultBinary, v)
            }
            HistoryUpdateAction::UpdateStructureData(v) => Self::from_encodable(
                ObjectId::UpdateStructureDataDetails_Encoding_DefaultBinary,
                v,
            ),
            HistoryUpdateAction::UpdateEvent(v) => {
                Self::from_encodable(ObjectId::UpdateEventDetails_Encoding_DefaultBinary, v)
            }
            HistoryUpdateAction::DeleteRawModified(v) => {
                Self::from_encodable(ObjectId::DeleteRawModifiedDetails_Encoding_DefaultBinary, v)
            }
            HistoryUpdateAction::DeleteAtTime(v) => {
                Self::from_encodable(ObjectId::DeleteAtTimeDetails_Encoding_DefaultBinary, v)
            }
            HistoryUpdateAction::DeleteEvent(v) => {
                Self::from_encodable(ObjectId::DeleteEventDetails_Encoding_DefaultBinary, v)
            }
        }
    }
}

impl Session {
    /// Reads the value of nodes by sending a [`ReadRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.10.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_read` - A list of [`ReadValueId`] to be read by the server.
    /// * `timestamps_to_return` - The [`TimestampsToReturn`] for each node, Both, Server, Source or None
    /// * `max_age` - The maximum age of value to read in milliseconds. Read the service description
    ///   for details. Basically it will attempt to read a value within the age range or
    ///   attempt to read a new value. If 0 the server will attempt to read a new value from the datasource.
    ///   If set to `i32::MAX` or greater, the server shall attempt to get a cached value.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<DataValue>)` - A list of [`DataValue`] corresponding to each read operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn read(
        &self,
        nodes_to_read: &[ReadValueId],
        timestamps_to_return: TimestampsToReturn,
        max_age: f64,
    ) -> Result<Vec<DataValue>, StatusCode> {
        if nodes_to_read.is_empty() {
            // No subscriptions
            session_error!(self, "read(), was not supplied with any nodes to read");
            Err(StatusCode::BadNothingToDo)
        } else {
            session_debug!(self, "read() requested to read nodes {:?}", nodes_to_read);
            let request = ReadRequest {
                request_header: self.make_request_header(),
                max_age,
                timestamps_to_return,
                nodes_to_read: Some(nodes_to_read.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::ReadResponse(response) = response {
                session_debug!(self, "read(), success");
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap_or_default())
            } else {
                session_error!(self, "read() value failed");
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Reads historical values or events of one or more nodes. The caller is expected to provide
    /// a HistoryReadAction enum which must be one of the following:
    ///
    /// * [`ReadEventDetails`]
    /// * [`ReadRawModifiedDetails`]
    /// * [`ReadProcessedDetails`]
    /// * [`ReadAtTimeDetails`]
    ///
    /// See OPC UA Part 4 - Services 5.10.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `history_read_details` - A history read operation.
    /// * `timestamps_to_return` - Enumeration of which timestamps to return.
    /// * `release_continuation_points` - Flag indicating whether to release the continuation point for the operation.
    /// * `nodes_to_read` - The list of [`HistoryReadValueId`] of the nodes to apply the history read operation to.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<HistoryReadResult>)` - A list of [`HistoryReadResult`] results corresponding to history read operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn history_read(
        &self,
        history_read_details: HistoryReadAction,
        timestamps_to_return: TimestampsToReturn,
        release_continuation_points: bool,
        nodes_to_read: &[HistoryReadValueId],
    ) -> Result<Vec<HistoryReadResult>, StatusCode> {
        // Turn the enum into an extension object
        let history_read_details = ExtensionObject::from(history_read_details);
        let request = HistoryReadRequest {
            request_header: self.make_request_header(),
            history_read_details,
            timestamps_to_return,
            release_continuation_points,
            nodes_to_read: if nodes_to_read.is_empty() {
                None
            } else {
                Some(nodes_to_read.to_vec())
            },
        };
        session_debug!(
            self,
            "history_read() requested to read nodes {:?}",
            nodes_to_read
        );
        let response = self.send(request).await?;
        if let SupportedMessage::HistoryReadResponse(response) = response {
            session_debug!(self, "history_read(), success");
            process_service_result(&response.response_header)?;
            Ok(response.results.unwrap_or_default())
        } else {
            session_error!(self, "history_read() value failed");
            Err(process_unexpected_response(response))
        }
    }

    /// Writes values to nodes by sending a [`WriteRequest`] to the server. Note that some servers may reject DataValues
    /// containing source or server timestamps.
    ///
    /// See OPC UA Part 4 - Services 5.10.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_write` - A list of [`WriteValue`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of [`StatusCode`] results corresponding to each write operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn write(
        &self,
        nodes_to_write: &[WriteValue],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if nodes_to_write.is_empty() {
            // No subscriptions
            session_error!(self, "write() was not supplied with any nodes to write");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = WriteRequest {
                request_header: self.make_request_header(),
                nodes_to_write: Some(nodes_to_write.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::WriteResponse(response) = response {
                session_debug!(self, "write(), success");
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap_or_default())
            } else {
                session_error!(self, "write() failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    /// Updates historical values. The caller is expected to provide one or more history update operations
    /// in a slice of HistoryUpdateAction enums which are one of the following:
    ///
    /// * [`UpdateDataDetails`]
    /// * [`UpdateStructureDataDetails`]
    /// * [`UpdateEventDetails`]
    /// * [`DeleteRawModifiedDetails`]
    /// * [`DeleteAtTimeDetails`]
    /// * [`DeleteEventDetails`]
    ///
    /// See OPC UA Part 4 - Services 5.10.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `history_update_details` - A list of history update operations.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ClientHistoryUpdateResult>)` - A list of [`ClientHistoryUpdateResult`] results corresponding to history update operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn history_update(
        &self,
        history_update_details: &[HistoryUpdateAction],
    ) -> Result<Vec<HistoryUpdateResult>, StatusCode> {
        if history_update_details.is_empty() {
            // No subscriptions
            session_error!(
                self,
                "history_update(), was not supplied with any detail to update"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            // Turn the enums into ExtensionObjects
            let history_update_details = history_update_details
                .iter()
                .map(ExtensionObject::from)
                .collect::<Vec<ExtensionObject>>();

            let request = HistoryUpdateRequest {
                request_header: self.make_request_header(),
                history_update_details: Some(history_update_details.to_vec()),
            };
            let response = self.send(request).await?;
            if let SupportedMessage::HistoryUpdateResponse(response) = response {
                session_debug!(self, "history_update(), success");
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap_or_default())
            } else {
                session_error!(self, "history_update() failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }
}
