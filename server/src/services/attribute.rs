use std::{
    result::Result,
    sync::{Arc, RwLock},
};

use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_core::supported_message::SupportedMessage;

use crate::{
    address_space::{AddressSpace, node::{HasNodeId, NodeType}, UserAccessLevel},
    services::Service,
    session::Session,
    state::ServerState,
};

enum ReadDetails {
    ReadEventDetails(ReadEventDetails),
    ReadRawModifiedDetails(ReadRawModifiedDetails),
    ReadProcessedDetails(ReadProcessedDetails),
    ReadAtTimeDetails(ReadAtTimeDetails),
}

enum UpdateDetails {
    UpdateDataDetails(UpdateDataDetails),
    UpdateStructureDataDetails(UpdateStructureDataDetails),
    UpdateEventDetails(UpdateEventDetails),
    DeleteRawModifiedDetails(DeleteRawModifiedDetails),
    DeleteAtTimeDetails(DeleteAtTimeDetails),
    DeleteEventDetails(DeleteEventDetails),
}

/// The attribute service. Allows attributes to be read and written from the address space.
pub(crate) struct AttributeService {}

impl Service for AttributeService {
    fn name(&self) -> String { String::from("AttributeService") }
}

impl AttributeService {
    pub fn new() -> AttributeService {
        AttributeService {}
    }

    /// Used to read historical values or Events of one or more Nodes. For
    /// constructed Attribute values whose elements are indexed, such as an array, this Service
    /// allows Clients to read the entire set of indexed values as a composite, to read individual
    /// elements or to read ranges of elements of the composite. Servers may make historical
    /// values available to Clients using this Service, although the historical values themselves
    /// are not visible in the AddressSpace.
    pub fn read(&self, _server_state: Arc<RwLock<ServerState>>, session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>, request: &ReadRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_read) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else if request.max_age < 0f64 {
            // Negative values are invalid for max_age
            warn!("ReadRequest max age is invalid");
            self.service_fault(&request.request_header, StatusCode::BadMaxAgeInvalid)
        } else {
            let nodes_to_read = request.nodes_to_read.as_ref().unwrap();
            // Read nodes and their attributes
            let session = trace_read_lock_unwrap!(session);
            let address_space = trace_read_lock_unwrap!(address_space);
            let timestamps_to_return = request.timestamps_to_return;
            let results = nodes_to_read.iter().map(|node_to_read| {
                Self::read_node_value(&session, &address_space, node_to_read, request.max_age, timestamps_to_return)
            }).collect();

            let diagnostic_infos = None;
            let response = ReadResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results: Some(results),
                diagnostic_infos,
            };
            response.into()
        }
    }

    /// Used to read historical values
    pub fn history_read(&self, server_state: Arc<RwLock<ServerState>>, _session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>, request: &HistoryReadRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_read) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let decoding_limits = {
                let server_state = trace_read_lock_unwrap!(server_state);
                server_state.decoding_limits()
            };
            match Self::do_history_read_details(&decoding_limits, server_state, address_space, request) {
                Ok(results) => {
                    let diagnostic_infos = None;
                    let response = HistoryReadResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        results: Some(results),
                        diagnostic_infos,
                    };
                    response.into()
                }
                Err(status_code) => {
                    self.service_fault(&request.request_header, status_code)
                }
            }
        }
    }

    /// Used to write values to one or more Attributes of one or more Nodes. For
    /// constructed Attribute values whose elements are indexed, such as an array, this Service
    /// allows Clients to write the entire set of indexed values as a composite, to write individual
    /// elements or to write ranges of elements of the composite.
    pub fn write(&self, _server_state: Arc<RwLock<ServerState>>, session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>, request: &WriteRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_write) {
            debug!("Empty list passed to write {:?}", request);
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            // TODO audit - generate AuditWriteUpdateEventType event
            let session = trace_read_lock_unwrap!(session);
            let mut address_space = trace_write_lock_unwrap!(address_space);
            let results = request.nodes_to_write.as_ref().unwrap().iter().map(|node_to_write| {
                Self::write_node_value(&session, &mut address_space, node_to_write)
            }).collect();

            let diagnostic_infos = None;
            WriteResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results: Some(results),
                diagnostic_infos,
            }.into()
        }
    }

    /// Used to update or update historical values
    pub fn history_update(&self, server_state: Arc<RwLock<ServerState>>, _session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>, request: &HistoryUpdateRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.history_update_details) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            // TODO audit - generate AuditHistoryUpdateEventType event
            let decoding_limits = {
                let server_state = trace_read_lock_unwrap!(server_state);
                server_state.decoding_limits()
            };
            let history_update_details = request.history_update_details.as_ref().unwrap();
            let results = history_update_details.iter().map(|u| {
                // Decode the update/delete action
                let (status_code, operation_results) = Self::do_history_update_details(&decoding_limits, server_state.clone(), address_space.clone(), u);
                HistoryUpdateResult {
                    status_code,
                    operation_results,
                    diagnostic_infos: None,
                }
            }).collect();
            HistoryUpdateResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results: Some(results),
                diagnostic_infos: None,
            }.into()
        }
    }

    fn node_id_to_action(node_id: &NodeId, actions: &[ObjectId]) -> Result<ObjectId, ()> {
        let object_id = node_id.as_object_id()?;
        actions.iter().find(|v| object_id == **v)
            .map(|v| *v)
            .ok_or(())
    }

    fn node_id_to_historical_read_action(node_id: &NodeId) -> Result<ObjectId, ()> {
        Self::node_id_to_action(node_id, &[
            ObjectId::ReadEventDetails_Encoding_DefaultBinary,
            ObjectId::ReadRawModifiedDetails_Encoding_DefaultBinary,
            ObjectId::ReadProcessedDetails_Encoding_DefaultBinary,
            ObjectId::ReadAtTimeDetails_Encoding_DefaultBinary
        ])
    }

    fn node_id_to_historical_update_action(node_id: &NodeId) -> Result<ObjectId, ()> {
        Self::node_id_to_action(node_id, &[
            ObjectId::UpdateDataDetails_Encoding_DefaultBinary,
            ObjectId::UpdateStructureDataDetails_Encoding_DefaultBinary,
            ObjectId::UpdateEventDetails_Encoding_DefaultBinary,
            ObjectId::DeleteRawModifiedDetails_Encoding_DefaultBinary,
            ObjectId::DeleteAtTimeDetails_Encoding_DefaultBinary,
            ObjectId::DeleteEventDetails_Encoding_DefaultBinary
        ])
    }

    fn decode_history_read_details(history_read_details: &ExtensionObject, decoding_limits: &DecodingLimits) -> Result<ReadDetails, StatusCode> {
        let action = Self::node_id_to_historical_read_action(&history_read_details.node_id)
            .map_err(|_| StatusCode::BadHistoryOperationInvalid)?;
        match action {
            ObjectId::ReadEventDetails_Encoding_DefaultBinary => Ok(ReadDetails::ReadEventDetails(history_read_details.decode_inner::<ReadEventDetails>(&decoding_limits)?)),
            ObjectId::ReadRawModifiedDetails_Encoding_DefaultBinary => Ok(ReadDetails::ReadRawModifiedDetails(history_read_details.decode_inner::<ReadRawModifiedDetails>(&decoding_limits)?)),
            ObjectId::ReadProcessedDetails_Encoding_DefaultBinary => Ok(ReadDetails::ReadProcessedDetails(history_read_details.decode_inner::<ReadProcessedDetails>(&decoding_limits)?)),
            ObjectId::ReadAtTimeDetails_Encoding_DefaultBinary => Ok(ReadDetails::ReadAtTimeDetails(history_read_details.decode_inner::<ReadAtTimeDetails>(&decoding_limits)?)),
            _ => panic!()
        }
    }

    fn decode_history_update_details(history_update_details: &ExtensionObject, decoding_limits: &DecodingLimits) -> Result<UpdateDetails, StatusCode> {
        let action = Self::node_id_to_historical_update_action(&history_update_details.node_id)
            .map_err(|_| StatusCode::BadHistoryOperationInvalid)?;
        match action {
            ObjectId::UpdateDataDetails_Encoding_DefaultBinary => Ok(UpdateDetails::UpdateDataDetails(history_update_details.decode_inner::<UpdateDataDetails>(&decoding_limits)?)),
            ObjectId::UpdateStructureDataDetails_Encoding_DefaultBinary => Ok(UpdateDetails::UpdateStructureDataDetails(history_update_details.decode_inner::<UpdateStructureDataDetails>(&decoding_limits)?)),
            ObjectId::UpdateEventDetails_Encoding_DefaultBinary => Ok(UpdateDetails::UpdateEventDetails(history_update_details.decode_inner::<UpdateEventDetails>(&decoding_limits)?)),
            ObjectId::DeleteRawModifiedDetails_Encoding_DefaultBinary => Ok(UpdateDetails::DeleteRawModifiedDetails(history_update_details.decode_inner::<DeleteRawModifiedDetails>(&decoding_limits)?)),
            ObjectId::DeleteAtTimeDetails_Encoding_DefaultBinary => Ok(UpdateDetails::DeleteAtTimeDetails(history_update_details.decode_inner::<DeleteAtTimeDetails>(&decoding_limits)?)),
            ObjectId::DeleteEventDetails_Encoding_DefaultBinary => Ok(UpdateDetails::DeleteEventDetails(history_update_details.decode_inner::<DeleteEventDetails>(&decoding_limits)?)),
            _ => panic!()
        }
    }

    fn do_history_update_details(decoding_limits: &DecodingLimits, server_state: Arc<RwLock<ServerState>>, address_space: Arc<RwLock<AddressSpace>>, u: &ExtensionObject) -> (StatusCode, Option<Vec<StatusCode>>) {
        match Self::decode_history_update_details(u, &decoding_limits) {
            Ok(details) => {
                let server_state = trace_read_lock_unwrap!(server_state);
                let address_space = address_space.clone();
                // Call the provider (data or event)
                let result = match details {
                    UpdateDetails::UpdateDataDetails(details) => {
                        if let Some(ref historical_data_provider) = server_state.historical_data_provider.as_ref() {
                            historical_data_provider.update_data_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::UpdateStructureDataDetails(details) => {
                        if let Some(ref historical_data_provider) = server_state.historical_data_provider.as_ref() {
                            historical_data_provider.update_structure_data_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::UpdateEventDetails(details) => {
                        if let Some(ref historical_event_provider) = server_state.historical_event_provider.as_ref() {
                            historical_event_provider.update_event_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::DeleteRawModifiedDetails(details) => {
                        if let Some(ref historical_data_provider) = server_state.historical_data_provider.as_ref() {
                            historical_data_provider.delete_raw_modified_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::DeleteAtTimeDetails(details) => {
                        if let Some(ref historical_data_provider) = server_state.historical_data_provider.as_ref() {
                            historical_data_provider.delete_at_time_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::DeleteEventDetails(details) => {
                        if let Some(ref historical_event_provider) = server_state.historical_event_provider.as_ref() {
                            historical_event_provider.delete_event_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                };
                match result {
                    Ok(operation_results) => (StatusCode::Good, Some(operation_results)),
                    Err(status_code) => (status_code, None)
                }
            }
            Err(status_code) => (status_code, None)
        }
    }

    fn do_history_read_details(decoding_limits: &DecodingLimits, server_state: Arc<RwLock<ServerState>>, address_space: Arc<RwLock<AddressSpace>>, request: &HistoryReadRequest) -> Result<Vec<HistoryReadResult>, StatusCode> {
        // Validate the action being performed
        let nodes_to_read = &request.nodes_to_read.as_ref().unwrap();
        let timestamps_to_return = request.timestamps_to_return;
        let release_continuation_points = request.release_continuation_points;
        let read_details = Self::decode_history_read_details(&request.history_read_details, &decoding_limits)?;

        let server_state = trace_read_lock_unwrap!(server_state);
        let results = match read_details {
            ReadDetails::ReadEventDetails(details) => {
                let historical_event_provider = server_state.historical_event_provider.as_ref().ok_or(StatusCode::BadHistoryOperationUnsupported)?;
                historical_event_provider.read_event_details(address_space, details, timestamps_to_return, release_continuation_points, &nodes_to_read)?
            }
            ReadDetails::ReadRawModifiedDetails(details) => {
                let historical_data_provider = server_state.historical_data_provider.as_ref().ok_or(StatusCode::BadHistoryOperationUnsupported)?;
                historical_data_provider.read_raw_modified_details(address_space, details, timestamps_to_return, release_continuation_points, &nodes_to_read)?
            }
            ReadDetails::ReadProcessedDetails(details) => {
                let historical_data_provider = server_state.historical_data_provider.as_ref().ok_or(StatusCode::BadHistoryOperationUnsupported)?;
                historical_data_provider.read_processed_details(address_space, details, timestamps_to_return, release_continuation_points, &nodes_to_read)?
            }
            ReadDetails::ReadAtTimeDetails(details) => {
                let historical_data_provider = server_state.historical_data_provider.as_ref().ok_or(StatusCode::BadHistoryOperationUnsupported)?;
                historical_data_provider.read_at_time_details(address_space, details, timestamps_to_return, release_continuation_points, &nodes_to_read)?
            }
        };
        Ok(results)
    }

    fn read_node_value(session: &Session, address_space: &AddressSpace, node_to_read: &ReadValueId, max_age: f64, timestamps_to_return: TimestampsToReturn) -> DataValue {
        // Node node found
        let mut result_value = DataValue::null();
        if let Some(node) = address_space.find_node(&node_to_read.node_id) {
            if let Ok(attribute_id) = AttributeId::from_u32(node_to_read.attribute_id) {
                let index_range = match node_to_read.index_range.as_ref().parse::<NumericRange>()
                    .map_err(|_| StatusCode::BadIndexRangeInvalid) {
                    Ok(index_range) => index_range,
                    Err(err) => {
                        return DataValue {
                            value: None,
                            status: Some(err),
                            source_timestamp: None,
                            source_picoseconds: None,
                            server_timestamp: None,
                            server_picoseconds: None,
                        };
                    }
                };

                if !Self::is_readable(session, &node, attribute_id) {
                    result_value.status = Some(StatusCode::BadNotReadable);
                } else if let Some(attribute) = node.as_node().get_attribute_max_age(attribute_id, index_range, &node_to_read.data_encoding, max_age) {
                    // If caller was reading the user access level, this needs to be modified to
                    // take account of the effective level based on who is logged in.
                    let value = if attribute_id == AttributeId::UserAccessLevel {
                        if let Some(value) = attribute.value {
                            if let Variant::Byte(value) = value {
                                // The bits from the node are further modified by the session
                                let user_access_level = UserAccessLevel::from_bits_truncate(value);
                                let user_access_level = session.effective_user_access_level(user_access_level, &node.node_id(), attribute_id);
                                Some(Variant::from(user_access_level.bits()))
                            } else {
                                Some(value)
                            }
                        } else {
                            None
                        }
                    } else {
                        attribute.value.clone()
                    };

                    // Result value is clone from the attribute
                    result_value.value = value;
                    result_value.status = attribute.status;
                    match timestamps_to_return {
                        TimestampsToReturn::Source => {
                            result_value.source_timestamp = attribute.source_timestamp.clone();
                            result_value.source_picoseconds = attribute.source_picoseconds;
                        }
                        TimestampsToReturn::Server => {
                            result_value.server_timestamp = attribute.server_timestamp.clone();
                            result_value.server_picoseconds = attribute.server_picoseconds;
                        }
                        TimestampsToReturn::Both => {
                            result_value.source_timestamp = attribute.source_timestamp.clone();
                            result_value.source_picoseconds = attribute.source_picoseconds;
                            result_value.server_timestamp = attribute.server_timestamp.clone();
                            result_value.server_picoseconds = attribute.server_picoseconds;
                        }
                        TimestampsToReturn::Neither | TimestampsToReturn::Invalid => {
                            // Nothing needs to change
                        }
                    }
                } else {
                    result_value.status = Some(StatusCode::BadAttributeIdInvalid);
                }
            } else {
                warn!("Attribute id {} is invalid", node_to_read.attribute_id);
                result_value.status = Some(StatusCode::BadAttributeIdInvalid);
            }
        } else {
            warn!("Cannot find node id {:?}", node_to_read.node_id);
            result_value.status = Some(StatusCode::BadNodeIdUnknown);
        }
        result_value
    }

    fn user_access_level(session: &Session, node: &NodeType, attribute_id: AttributeId) -> UserAccessLevel {
        let user_access_level = if let NodeType::Variable(ref node) = node {
            node.user_access_level()
        } else {
            UserAccessLevel::CURRENT_READ
        };
        session.effective_user_access_level(user_access_level, &node.node_id(), attribute_id)
    }

    fn is_readable(session: &Session, node: &NodeType, attribute_id: AttributeId) -> bool {
        // TODO session for current user
        // Check for access level, user access level
        Self::user_access_level(session, node, attribute_id).contains(UserAccessLevel::CURRENT_READ)
    }

    fn is_writable(session: &Session, node: &NodeType, attribute_id: AttributeId) -> bool {
        // TODO session for current user
        // For a variable, the access level controls access to the variable
        if let NodeType::Variable(_) = node {
            if attribute_id == AttributeId::Value {
                return Self::user_access_level(session, node, attribute_id).contains(UserAccessLevel::CURRENT_WRITE);
            }
        }

        if let Some(write_mask) = node.as_node().write_mask() {
            match attribute_id {
                AttributeId::Value => if let NodeType::VariableType(_) = node {
                    write_mask.contains(WriteMask::VALUE_FOR_VARIABLE_TYPE)
                } else {
                    false
                }
                AttributeId::NodeId => write_mask.contains(WriteMask::NODE_ID),
                AttributeId::NodeClass => write_mask.contains(WriteMask::NODE_CLASS),
                AttributeId::BrowseName => write_mask.contains(WriteMask::BROWSE_NAME),
                AttributeId::DisplayName => write_mask.contains(WriteMask::DISPLAY_NAME),
                AttributeId::Description => write_mask.contains(WriteMask::DESCRIPTION),
                AttributeId::WriteMask => write_mask.contains(WriteMask::WRITE_MASK),
                AttributeId::UserWriteMask => write_mask.contains(WriteMask::USER_WRITE_MASK),
                AttributeId::IsAbstract => write_mask.contains(WriteMask::IS_ABSTRACT),
                AttributeId::Symmetric => write_mask.contains(WriteMask::SYMMETRIC),
                AttributeId::InverseName => write_mask.contains(WriteMask::INVERSE_NAME),
                AttributeId::ContainsNoLoops => write_mask.contains(WriteMask::CONTAINS_NO_LOOPS),
                AttributeId::EventNotifier => write_mask.contains(WriteMask::EVENT_NOTIFIER),
                AttributeId::DataType => write_mask.contains(WriteMask::DATA_TYPE),
                AttributeId::ValueRank => write_mask.contains(WriteMask::VALUE_RANK),
                AttributeId::ArrayDimensions => write_mask.contains(WriteMask::ARRAY_DIMENSIONS),
                AttributeId::AccessLevel => write_mask.contains(WriteMask::ACCESS_LEVEL),
                AttributeId::UserAccessLevel => write_mask.contains(WriteMask::USER_ACCESS_LEVEL),
                AttributeId::MinimumSamplingInterval => write_mask.contains(WriteMask::MINIMUM_SAMPLING_INTERVAL),
                AttributeId::Historizing => write_mask.contains(WriteMask::HISTORIZING),
                AttributeId::Executable => write_mask.contains(WriteMask::EXECUTABLE),
                AttributeId::UserExecutable => write_mask.contains(WriteMask::USER_EXECUTABLE),
                AttributeId::DataTypeDefinition => write_mask.contains(WriteMask::DATA_TYPE_DEFINITION),
                AttributeId::RolePermissions => write_mask.contains(WriteMask::ROLE_PERMISSIONS),
                AttributeId::AccessRestrictions => write_mask.contains(WriteMask::ACCESS_RESTRICTIONS),
                AttributeId::AccessLevelEx => write_mask.contains(WriteMask::ACCESS_LEVEL_EX),
                AttributeId::UserRolePermissions => false // Reserved
            }
        } else {
            false
        }
    }

    /*
    fn is_history_readable(session: &Session, node: &NodeType) -> bool {
        Self::user_access_level(session, node, AttributeId::Value).contains(UserAccessLevel::HISTORY_READ)
    }

    fn is_history_updateable(session: &Session, node: &NodeType) -> bool {
        Self::user_access_level(session, node, AttributeId::Value).contains(UserAccessLevel::HISTORY_WRITE)
    }
    */

    fn write_node_value(session: &Session, address_space: &mut AddressSpace, node_to_write: &WriteValue) -> StatusCode {
        if let Some(node) = address_space.find_node_mut(&node_to_write.node_id) {
            if let Ok(attribute_id) = AttributeId::from_u32(node_to_write.attribute_id) {
                if !Self::is_writable(session, &node, attribute_id) {
                    StatusCode::BadNotWritable
                } else if !node_to_write.index_range.is_null() {
                    // Index ranges are not supported
                    error!("Server does not support indexes in write");
                    StatusCode::BadWriteNotSupported
//                } else if node_to_write.value.server_timestamp.is_some() || node_to_write.value.server_picoseconds.is_some() ||
//                    node_to_write.value.source_timestamp.is_some() || node_to_write.value.source_picoseconds.is_some() {
//                    error!("Server does not support timestamps in write");
//                    StatusCode::BadWriteNotSupported
                } else if let Some(ref value) = node_to_write.value.value {
                    let node = node.as_mut_node();
                    if let Err(err) = node.set_attribute(attribute_id, value.clone()) {
                        err
                    } else {
                        StatusCode::Good
                    }
                } else {
                    error!("Server does not support missing value in write");
                    StatusCode::BadWriteNotSupported
                }
            } else {
                warn!("Attribute id {} is invalid", node_to_write.attribute_id);
                StatusCode::BadAttributeIdInvalid
            }
        } else {
            warn!("Cannot find node id {:?}", node_to_write.node_id);
            StatusCode::BadNodeIdUnknown
        }
    }
}
