// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{result::Result, sync::Arc};

use crate::{
    core::supported_message::SupportedMessage,
    sync::*,
    types::{status_code::StatusCode, *},
};

use crate::server::{
    address_space::{
        node::{HasNodeId, NodeBase, NodeType},
        variable::Variable,
        AddressSpace, UserAccessLevel,
    },
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
    fn name(&self) -> String {
        String::from("AttributeService")
    }
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
    pub fn read(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &ReadRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_read) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else if request.max_age < 0f64 {
            // Negative values are invalid for max_age
            warn!("ReadRequest max age is invalid");
            self.service_fault(&request.request_header, StatusCode::BadMaxAgeInvalid)
        } else if request.timestamps_to_return == TimestampsToReturn::Invalid {
            warn!("ReadRequest invalid timestamps to return");
            self.service_fault(
                &request.request_header,
                StatusCode::BadTimestampsToReturnInvalid,
            )
        } else {
            let server_state = trace_read_lock!(server_state);
            let nodes_to_read = request.nodes_to_read.as_ref().unwrap();
            if nodes_to_read.len() <= server_state.operational_limits.max_nodes_per_read {
                // Read nodes and their attributes
                let session = trace_read_lock!(session);
                let address_space = trace_read_lock!(address_space);
                let timestamps_to_return = request.timestamps_to_return;
                let results = nodes_to_read
                    .iter()
                    .map(|node_to_read| {
                        Self::read_node_value(
                            &session,
                            &address_space,
                            node_to_read,
                            request.max_age,
                            timestamps_to_return,
                        )
                    })
                    .collect();

                let diagnostic_infos = None;
                let response = ReadResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos,
                };
                response.into()
            } else {
                warn!("ReadRequest too many nodes to read {}", nodes_to_read.len());
                self.service_fault(&request.request_header, StatusCode::BadTooManyOperations)
            }
        }
    }

    /// Used to read historical values
    pub fn history_read(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        _session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &HistoryReadRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_read) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let decoding_options = {
                let server_state = trace_read_lock!(server_state);
                server_state.decoding_options()
            };
            match Self::do_history_read_details(
                &decoding_options,
                server_state,
                address_space,
                request,
            ) {
                Ok(results) => {
                    let diagnostic_infos = None;
                    let response = HistoryReadResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        results: Some(results),
                        diagnostic_infos,
                    };
                    response.into()
                }
                Err(status_code) => self.service_fault(&request.request_header, status_code),
            }
        }
    }

    /// Used to write values to one or more Attributes of one or more Nodes. For
    /// constructed Attribute values whose elements are indexed, such as an array, this Service
    /// allows Clients to write the entire set of indexed values as a composite, to write individual
    /// elements or to write ranges of elements of the composite.
    pub fn write(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &WriteRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_write) {
            debug!("Empty list passed to write {:?}", request);
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            // TODO audit - generate AuditWriteUpdateEventType event
            let server_state = trace_read_lock!(server_state);
            let session = trace_read_lock!(session);
            let mut address_space = trace_write_lock!(address_space);

            let nodes_to_write = request.nodes_to_write.as_ref().unwrap();
            if nodes_to_write.len() <= server_state.operational_limits.max_nodes_per_write {
                let results = nodes_to_write
                    .iter()
                    .map(|node_to_write| {
                        Self::write_node_value(&session, &mut address_space, node_to_write)
                    })
                    .collect();

                let diagnostic_infos = None;
                WriteResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos,
                }
                .into()
            } else {
                warn!(
                    "WriteRequest too many nodes to write {}",
                    nodes_to_write.len()
                );
                self.service_fault(&request.request_header, StatusCode::BadTooManyOperations)
            }
        }
    }

    /// Used to update or update historical values
    pub fn history_update(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        _session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &HistoryUpdateRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.history_update_details) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            // TODO audit - generate AuditHistoryUpdateEventType event
            let decoding_options = {
                let server_state = trace_read_lock!(server_state);
                server_state.decoding_options()
            };
            let history_update_details = request.history_update_details.as_ref().unwrap();
            let results = history_update_details
                .iter()
                .map(|u| {
                    // Decode the update/delete action
                    let (status_code, operation_results) = Self::do_history_update_details(
                        &decoding_options,
                        server_state.clone(),
                        address_space.clone(),
                        u,
                    );
                    HistoryUpdateResult {
                        status_code,
                        operation_results,
                        diagnostic_infos: None,
                    }
                })
                .collect();
            HistoryUpdateResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results: Some(results),
                diagnostic_infos: None,
            }
            .into()
        }
    }

    fn node_id_to_action(node_id: &NodeId, actions: &[ObjectId]) -> Result<ObjectId, ()> {
        let object_id = node_id.as_object_id().map_err(|_| ())?;
        actions.iter().find(|v| object_id == **v).copied().ok_or(())
    }

    fn node_id_to_historical_read_action(node_id: &NodeId) -> Result<ObjectId, ()> {
        Self::node_id_to_action(
            node_id,
            &[
                ObjectId::ReadEventDetails_Encoding_DefaultBinary,
                ObjectId::ReadRawModifiedDetails_Encoding_DefaultBinary,
                ObjectId::ReadProcessedDetails_Encoding_DefaultBinary,
                ObjectId::ReadAtTimeDetails_Encoding_DefaultBinary,
            ],
        )
    }

    fn node_id_to_historical_update_action(node_id: &NodeId) -> Result<ObjectId, ()> {
        Self::node_id_to_action(
            node_id,
            &[
                ObjectId::UpdateDataDetails_Encoding_DefaultBinary,
                ObjectId::UpdateStructureDataDetails_Encoding_DefaultBinary,
                ObjectId::UpdateEventDetails_Encoding_DefaultBinary,
                ObjectId::DeleteRawModifiedDetails_Encoding_DefaultBinary,
                ObjectId::DeleteAtTimeDetails_Encoding_DefaultBinary,
                ObjectId::DeleteEventDetails_Encoding_DefaultBinary,
            ],
        )
    }

    fn decode_history_read_details(
        history_read_details: &ExtensionObject,
        decoding_options: &DecodingOptions,
    ) -> Result<ReadDetails, StatusCode> {
        let action = Self::node_id_to_historical_read_action(&history_read_details.node_id)
            .map_err(|_| StatusCode::BadHistoryOperationInvalid)?;
        match action {
            ObjectId::ReadEventDetails_Encoding_DefaultBinary => Ok(ReadDetails::ReadEventDetails(
                history_read_details.decode_inner::<ReadEventDetails>(decoding_options)?,
            )),
            ObjectId::ReadRawModifiedDetails_Encoding_DefaultBinary => {
                Ok(ReadDetails::ReadRawModifiedDetails(
                    history_read_details
                        .decode_inner::<ReadRawModifiedDetails>(decoding_options)?,
                ))
            }
            ObjectId::ReadProcessedDetails_Encoding_DefaultBinary => {
                Ok(ReadDetails::ReadProcessedDetails(
                    history_read_details.decode_inner::<ReadProcessedDetails>(decoding_options)?,
                ))
            }
            ObjectId::ReadAtTimeDetails_Encoding_DefaultBinary => {
                Ok(ReadDetails::ReadAtTimeDetails(
                    history_read_details.decode_inner::<ReadAtTimeDetails>(decoding_options)?,
                ))
            }
            _ => panic!(),
        }
    }

    fn decode_history_update_details(
        history_update_details: &ExtensionObject,
        decoding_options: &DecodingOptions,
    ) -> Result<UpdateDetails, StatusCode> {
        let action = Self::node_id_to_historical_update_action(&history_update_details.node_id)
            .map_err(|_| StatusCode::BadHistoryOperationInvalid)?;
        match action {
            ObjectId::UpdateDataDetails_Encoding_DefaultBinary => {
                Ok(UpdateDetails::UpdateDataDetails(
                    history_update_details.decode_inner::<UpdateDataDetails>(decoding_options)?,
                ))
            }
            ObjectId::UpdateStructureDataDetails_Encoding_DefaultBinary => {
                Ok(UpdateDetails::UpdateStructureDataDetails(
                    history_update_details
                        .decode_inner::<UpdateStructureDataDetails>(decoding_options)?,
                ))
            }
            ObjectId::UpdateEventDetails_Encoding_DefaultBinary => {
                Ok(UpdateDetails::UpdateEventDetails(
                    history_update_details.decode_inner::<UpdateEventDetails>(decoding_options)?,
                ))
            }
            ObjectId::DeleteRawModifiedDetails_Encoding_DefaultBinary => {
                Ok(UpdateDetails::DeleteRawModifiedDetails(
                    history_update_details
                        .decode_inner::<DeleteRawModifiedDetails>(decoding_options)?,
                ))
            }
            ObjectId::DeleteAtTimeDetails_Encoding_DefaultBinary => {
                Ok(UpdateDetails::DeleteAtTimeDetails(
                    history_update_details.decode_inner::<DeleteAtTimeDetails>(decoding_options)?,
                ))
            }
            ObjectId::DeleteEventDetails_Encoding_DefaultBinary => {
                Ok(UpdateDetails::DeleteEventDetails(
                    history_update_details.decode_inner::<DeleteEventDetails>(decoding_options)?,
                ))
            }
            _ => panic!(),
        }
    }

    fn do_history_update_details(
        decoding_options: &DecodingOptions,
        server_state: Arc<RwLock<ServerState>>,
        address_space: Arc<RwLock<AddressSpace>>,
        u: &ExtensionObject,
    ) -> (StatusCode, Option<Vec<StatusCode>>) {
        match Self::decode_history_update_details(u, decoding_options) {
            Ok(details) => {
                let server_state = trace_read_lock!(server_state);
                // Call the provider (data or event)
                let result = match details {
                    UpdateDetails::UpdateDataDetails(details) => {
                        if let Some(historical_data_provider) =
                            server_state.historical_data_provider.as_ref()
                        {
                            historical_data_provider.update_data_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::UpdateStructureDataDetails(details) => {
                        if let Some(historical_data_provider) =
                            server_state.historical_data_provider.as_ref()
                        {
                            historical_data_provider
                                .update_structure_data_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::UpdateEventDetails(details) => {
                        if let Some(historical_event_provider) =
                            server_state.historical_event_provider.as_ref()
                        {
                            historical_event_provider.update_event_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::DeleteRawModifiedDetails(details) => {
                        if let Some(historical_data_provider) =
                            server_state.historical_data_provider.as_ref()
                        {
                            historical_data_provider
                                .delete_raw_modified_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::DeleteAtTimeDetails(details) => {
                        if let Some(historical_data_provider) =
                            server_state.historical_data_provider.as_ref()
                        {
                            historical_data_provider.delete_at_time_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                    UpdateDetails::DeleteEventDetails(details) => {
                        if let Some(historical_event_provider) =
                            server_state.historical_event_provider.as_ref()
                        {
                            historical_event_provider.delete_event_details(address_space, details)
                        } else {
                            Err(StatusCode::BadHistoryOperationUnsupported)
                        }
                    }
                };
                match result {
                    Ok(operation_results) => (StatusCode::Good, Some(operation_results)),
                    Err(status_code) => (status_code, None),
                }
            }
            Err(status_code) => (status_code, None),
        }
    }

    fn do_history_read_details(
        decoding_options: &DecodingOptions,
        server_state: Arc<RwLock<ServerState>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &HistoryReadRequest,
    ) -> Result<Vec<HistoryReadResult>, StatusCode> {
        // TODO enforce operation limits

        // Validate the action being performed
        let nodes_to_read = &request.nodes_to_read.as_ref().unwrap();
        let timestamps_to_return = request.timestamps_to_return;
        let release_continuation_points = request.release_continuation_points;
        let read_details =
            Self::decode_history_read_details(&request.history_read_details, decoding_options)?;

        let server_state = trace_read_lock!(server_state);
        let results = match read_details {
            ReadDetails::ReadEventDetails(details) => {
                let historical_event_provider = server_state
                    .historical_event_provider
                    .as_ref()
                    .ok_or(StatusCode::BadHistoryOperationUnsupported)?;
                historical_event_provider.read_event_details(
                    address_space,
                    details,
                    timestamps_to_return,
                    release_continuation_points,
                    nodes_to_read,
                )?
            }
            ReadDetails::ReadRawModifiedDetails(details) => {
                let historical_data_provider = server_state
                    .historical_data_provider
                    .as_ref()
                    .ok_or(StatusCode::BadHistoryOperationUnsupported)?;
                historical_data_provider.read_raw_modified_details(
                    address_space,
                    details,
                    timestamps_to_return,
                    release_continuation_points,
                    nodes_to_read,
                )?
            }
            ReadDetails::ReadProcessedDetails(details) => {
                let historical_data_provider = server_state
                    .historical_data_provider
                    .as_ref()
                    .ok_or(StatusCode::BadHistoryOperationUnsupported)?;
                historical_data_provider.read_processed_details(
                    address_space,
                    details,
                    timestamps_to_return,
                    release_continuation_points,
                    nodes_to_read,
                )?
            }
            ReadDetails::ReadAtTimeDetails(details) => {
                let historical_data_provider = server_state
                    .historical_data_provider
                    .as_ref()
                    .ok_or(StatusCode::BadHistoryOperationUnsupported)?;
                historical_data_provider.read_at_time_details(
                    address_space,
                    details,
                    timestamps_to_return,
                    release_continuation_points,
                    nodes_to_read,
                )?
            }
        };
        Ok(results)
    }

    fn is_supported_data_encoding(data_encoding: &QualifiedName) -> bool {
        if data_encoding.is_null() {
            true
        } else {
            data_encoding.namespace_index == 0 && data_encoding.name.eq("Default Binary")
        }
    }

    fn read_node_value(
        session: &Session,
        address_space: &AddressSpace,
        node_to_read: &ReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> DataValue {
        // Node node found
        // debug!("read_node_value asked to read node id {}, attribute {}", node_to_read.node_id, node_to_read.attribute_id);
        let mut result_value = DataValue::null();
        if let Some(node) = address_space.find_node(&node_to_read.node_id) {
            if let Ok(attribute_id) = AttributeId::from_u32(node_to_read.attribute_id) {
                let index_range = match node_to_read
                    .index_range
                    .as_ref()
                    .parse::<NumericRange>()
                    .map_err(|_| StatusCode::BadIndexRangeInvalid)
                {
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

                if !Self::is_readable(session, node, attribute_id) {
                    // Can't read this node
                    debug!(
                        "read_node_value result for read node id {}, attribute {} is unreadable",
                        node_to_read.node_id, node_to_read.attribute_id
                    );
                    result_value.status = Some(StatusCode::BadNotReadable);
                } else if attribute_id != AttributeId::Value && index_range != NumericRange::None {
                    // Can't supply an index range on a non-Value attribute
                    debug!(
                        "read_node_value result for read node id {}, attribute {} is invalid range",
                        node_to_read.node_id, node_to_read.attribute_id
                    );
                    result_value.status = Some(StatusCode::BadIndexRangeNoData);
                } else if !Self::is_supported_data_encoding(&node_to_read.data_encoding) {
                    // Caller must request binary
                    debug!("read_node_value result for read node id {}, attribute {} is invalid data encoding", node_to_read.node_id, node_to_read.attribute_id);
                    result_value.status = Some(StatusCode::BadDataEncodingInvalid);
                } else if let Some(attribute) = node.as_node().get_attribute_max_age(
                    timestamps_to_return,
                    attribute_id,
                    index_range,
                    &node_to_read.data_encoding,
                    max_age,
                ) {
                    // If caller was reading the user access level, this needs to be modified to
                    // take account of the effective level based on who is logged in.
                    let value = if attribute_id == AttributeId::UserAccessLevel {
                        if let Some(value) = attribute.value {
                            if let Variant::Byte(value) = value {
                                // The bits from the node are further modified by the session
                                let user_access_level = UserAccessLevel::from_bits_truncate(value);
                                let user_access_level = session.effective_user_access_level(
                                    user_access_level,
                                    &node.node_id(),
                                    attribute_id,
                                );
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

                    if let Some(status_code) = attribute.status {
                        if status_code.is_bad() {
                            debug!("read_node_value result for read node id {}, attribute {} is bad {}", node_to_read.node_id, node_to_read.attribute_id, status_code);
                        }
                    }

                    // Timestamps to return only applies to variable value
                    if let NodeType::Variable(_) = node {
                        if attribute_id == AttributeId::Value {
                            match timestamps_to_return {
                                TimestampsToReturn::Source => {
                                    result_value.source_timestamp = attribute.source_timestamp;
                                    result_value.source_picoseconds = attribute.source_picoseconds;
                                }
                                TimestampsToReturn::Server => {
                                    result_value.server_timestamp = attribute.server_timestamp;
                                    result_value.server_picoseconds = attribute.server_picoseconds;
                                }
                                TimestampsToReturn::Both => {
                                    result_value.source_timestamp = attribute.source_timestamp;
                                    result_value.source_picoseconds = attribute.source_picoseconds;
                                    result_value.server_timestamp = attribute.server_timestamp;
                                    result_value.server_picoseconds = attribute.server_picoseconds;
                                }
                                TimestampsToReturn::Neither | TimestampsToReturn::Invalid => {
                                    // Nothing needs to change
                                }
                            }
                        }
                    }
                } else {
                    debug!(
                        "read_node_value result for read node id {}, attribute {} is invalid/1",
                        node_to_read.node_id, node_to_read.attribute_id
                    );
                    result_value.status = Some(StatusCode::BadAttributeIdInvalid);
                }
            } else {
                debug!(
                    "read_node_value result for read node id {}, attribute {} is invalid/2",
                    node_to_read.node_id, node_to_read.attribute_id
                );
                result_value.status = Some(StatusCode::BadAttributeIdInvalid);
            }
        } else {
            debug!(
                "read_node_value result for read node id {}, attribute {} cannot find node",
                node_to_read.node_id, node_to_read.attribute_id
            );
            result_value.status = Some(StatusCode::BadNodeIdUnknown);
        }
        result_value
    }

    fn user_access_level(
        session: &Session,
        node: &NodeType,
        attribute_id: AttributeId,
    ) -> UserAccessLevel {
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
                return Self::user_access_level(session, node, attribute_id)
                    .contains(UserAccessLevel::CURRENT_WRITE);
            }
        }

        if let Some(write_mask) = node.as_node().write_mask() {
            match attribute_id {
                AttributeId::Value => {
                    if let NodeType::VariableType(_) = node {
                        write_mask.contains(WriteMask::VALUE_FOR_VARIABLE_TYPE)
                    } else {
                        false
                    }
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
                AttributeId::MinimumSamplingInterval => {
                    write_mask.contains(WriteMask::MINIMUM_SAMPLING_INTERVAL)
                }
                AttributeId::Historizing => write_mask.contains(WriteMask::HISTORIZING),
                AttributeId::Executable => write_mask.contains(WriteMask::EXECUTABLE),
                AttributeId::UserExecutable => write_mask.contains(WriteMask::USER_EXECUTABLE),
                AttributeId::DataTypeDefinition => {
                    write_mask.contains(WriteMask::DATA_TYPE_DEFINITION)
                }
                AttributeId::RolePermissions => write_mask.contains(WriteMask::ROLE_PERMISSIONS),
                AttributeId::AccessRestrictions => {
                    write_mask.contains(WriteMask::ACCESS_RESTRICTIONS)
                }
                AttributeId::AccessLevelEx => write_mask.contains(WriteMask::ACCESS_LEVEL_EX),
                AttributeId::UserRolePermissions => false, // Reserved
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

    /// Determine if the value is writable to a Variable node's data type
    fn validate_value_to_write(
        address_space: &AddressSpace,
        variable: &Variable,
        value: &Variant,
    ) -> bool {
        // Get the value rank and data type of the variable
        let value_rank = variable.value_rank();
        let node_data_type = variable.data_type();

        let valid = if let Variant::Empty = value {
            // Assigning an empty value is permissible
            true
        } else if let Some(value_data_type) = value.scalar_data_type() {
            // Value is scalar. Check if the data type matches
            let data_type_matches = address_space.is_subtype(&value_data_type, &node_data_type);
            if !data_type_matches {
                // Check if the value to write is a byte string and the receiving node type a byte array.
                // This code is a mess just for some weird edge case in the spec that a write from
                // a byte string to a byte array should succeed
                match value {
                    Variant::ByteString(_) => {
                        if node_data_type == DataTypeId::Byte.into() {
                            match value_rank {
                                -2 | -3 | 1 => true,
                                _ => false,
                            }
                        } else {
                            false
                        }
                    }
                    _ => data_type_matches,
                }
            } else {
                true
            }
        } else if let Some(value_data_type) = value.array_data_type() {
            // TODO check that value is array of same dimensions
            address_space.is_subtype(&value_data_type, &node_data_type)
        } else {
            // Value should have a data type
            false
        };
        if !valid {
            debug!("Variable value validation did not pass, check value {:?} against var {} data type of {}", value, variable.node_id(), node_data_type);
        }
        valid
    }

    fn write_node_value(
        session: &Session,
        address_space: &mut AddressSpace,
        node_to_write: &WriteValue,
    ) -> StatusCode {
        if let Some(node) = address_space.find_node(&node_to_write.node_id) {
            if let Ok(attribute_id) = AttributeId::from_u32(node_to_write.attribute_id) {
                let index_range = node_to_write.index_range.as_ref().parse::<NumericRange>();

                if !Self::is_writable(session, node, attribute_id) {
                    StatusCode::BadNotWritable
                } else if attribute_id != AttributeId::Value && !node_to_write.index_range.is_null()
                {
                    // Index ranges are not supported on anything other than a value attribute
                    error!("Server does not support indexes for attributes other than Value");
                    StatusCode::BadWriteNotSupported
                //                 else if node_to_write.value.server_timestamp.is_some() || node_to_write.value.server_picoseconds.is_some() ||
                //                    node_to_write.value.source_timestamp.is_some() || node_to_write.value.source_picoseconds.is_some() {
                //                    error!("Server does not support timestamps in write");
                //                    StatusCode::BadWriteNotSupported
                } else if index_range.is_err() {
                    error!("Index range is invalid");
                    StatusCode::BadIndexRangeInvalid
                } else if let Some(ref value) = node_to_write.value.value {
                    let index_range = index_range.unwrap();

                    // This is a band-aid for Variable::Value which should check if the data type
                    // matches the written value. Note, that ALL attributes should check for subtypes
                    // but they don't. There should be a general purpose fn attribute_type(attribute_id) helper
                    // on the node impl that returns a datatype for the attribute regardless of node.
                    let data_type_valid = if attribute_id == AttributeId::Value {
                        match node {
                            NodeType::Variable(ref variable) => {
                                Self::validate_value_to_write(address_space, variable, value)
                            }
                            _ => true, // Other types don't have this attr but they will reject later during set
                        }
                    } else {
                        true
                    };
                    if !data_type_valid {
                        error!("Data type of value is invalid for writing to attribute");
                        StatusCode::BadTypeMismatch
                    } else {
                        let node = address_space.find_node_mut(&node_to_write.node_id).unwrap();
                        let result = if attribute_id == AttributeId::Value {
                            match node {
                                NodeType::Variable(ref mut variable) => variable
                                    .set_value(index_range, value.clone())
                                    .map_err(|err| {
                                        error!(
                                            "Value could not be set to node {} Value, error = {}",
                                            node_to_write.node_id, err
                                        );
                                        err
                                    }),
                                _ => Err(StatusCode::BadAttributeIdInvalid),
                            }
                        } else {
                            let node = node.as_mut_node();
                            node.set_attribute(attribute_id, value.clone())
                                .map_err(|err| {
                                    error!("Value could not be set to node {} attribute {:?}, error = {}", node_to_write.node_id, attribute_id, err);
                                    err
                                })
                        };
                        if let Err(err) = result {
                            err
                        } else {
                            StatusCode::Good
                        }
                    }
                } else {
                    error!("Server does not support missing value in write");
                    StatusCode::BadTypeMismatch
                }
            } else {
                warn!("Attribute id {} is invalid", node_to_write.attribute_id);
                StatusCode::BadAttributeIdInvalid
            }
        } else {
            warn!("Cannot find node id {}", node_to_write.node_id);
            StatusCode::BadNodeIdUnknown
        }
    }
}
