use std::result::Result;

use opcua_types::*;
use opcua_types::status_code::StatusCode;

use crate::{
    services::Service,
    address_space::{AccessLevel, AddressSpace, node::NodeType},
};

/// The attribute service. Allows attributes to be read and written from the address space.
pub(crate) struct AttributeService;

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
    pub fn read(&self, address_space: &AddressSpace, request: &ReadRequest) -> Result<SupportedMessage, StatusCode> {
        if is_empty_option_vec!(request.nodes_to_read) {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        } else if request.max_age < 0f64 {
            // Negative values are invalid for max_age
            warn!("ReadRequest max age is invalid");
            Ok(self.service_fault(&request.request_header, StatusCode::BadMaxAgeInvalid))
        } else {
            let nodes_to_read = request.nodes_to_read.as_ref().unwrap();

            // Read nodes and their attributes
            let timestamps_to_return = request.timestamps_to_return;
            let results = nodes_to_read.iter().map(|node_to_read| {
                Self::read_node_value(&address_space, node_to_read, request.max_age, timestamps_to_return)
            }).collect();

            let diagnostic_infos = None;
            let response = ReadResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results: Some(results),
                diagnostic_infos,
            };
            Ok(response.into())
        }
    }

    /// Used to write values to one or more Attributes of one or more Nodes. For
    /// constructed Attribute values whose elements are indexed, such as an array, this Service
    /// allows Clients to write the entire set of indexed values as a composite, to write individual
    /// elements or to write ranges of elements of the composite.
    pub fn write(&self, address_space: &mut AddressSpace, request: &WriteRequest) -> Result<SupportedMessage, StatusCode> {
        if is_empty_option_vec!(request.nodes_to_write) {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        } else {
            let results = request.nodes_to_write.as_ref().unwrap().iter().map(|node_to_write| {
                Self::write_node_value(address_space, node_to_write)
            }).collect();

            let diagnostic_infos = None;
            let response = WriteResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results: Some(results),
                diagnostic_infos,
            };
            Ok(response.into())
        }
    }

    fn read_node_value(address_space: &AddressSpace, node_to_read: &ReadValueId, max_age: f64, timestamps_to_return: TimestampsToReturn) -> DataValue {
        let mut result_value = DataValue {
            value: None,
            status: None,
            source_timestamp: None,
            source_picoseconds: None,
            server_timestamp: None,
            server_picoseconds: None,
        };
        // Node node found
        if let Some(node) = address_space.find_node(&node_to_read.node_id) {
            if let Ok(attribute_id) = AttributeId::from_u32(node_to_read.attribute_id) {
                if let Some(attribute) = node.as_node().get_attribute_max_age(attribute_id, max_age) {
                    let is_readable = Self::is_readable(&node);
                    if !is_readable {
                        result_value.status = Some(StatusCode::BadNotReadable)
                    } else if !node_to_read.index_range.is_null() {
                        // Index ranges are not supported
                        result_value.status = Some(StatusCode::BadNotReadable);
                    } else {
                        // Result value is clone from the attribute
                        result_value.value = attribute.value.clone();

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

    fn is_readable(node: &NodeType) -> bool {
        // Check for access level, user access level
        if let NodeType::Variable(ref node) = *node {
            if !node.access_level().contains(AccessLevel::CURRENT_READ) {
                return false;
            }
        }
        true
    }

    fn write_node_value(address_space: &mut AddressSpace, node_to_write: &WriteValue) -> StatusCode {
        if let Some(node) = address_space.find_node_mut(&node_to_write.node_id) {
            if let Ok(attribute_id) = AttributeId::from_u32(node_to_write.attribute_id) {
                if !Self::is_writable(&node, attribute_id) {
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

    fn is_writable(node: &NodeType, attribute_id: AttributeId) -> bool {
        // For a variable, the access level controls access to the variable
        if let NodeType::Variable(ref node) = node {
            if attribute_id == AttributeId::Value {
                return node.access_level().contains(AccessLevel::CURRENT_WRITE);
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
            }
        } else {
            false
        }
    }
}
