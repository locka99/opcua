use std::result::Result;

use opcua_types::*;

use server::ServerState;
use session::Session;
use services::Service;
use address_space::access_level;
use address_space::address_space::AddressSpace;
use address_space::node::NodeType;

pub struct AttributeService {}

impl Service for AttributeService {}

impl AttributeService {
    pub fn new() -> AttributeService {
        AttributeService {}
    }

    /// Spec:
    ///
    /// This Service is used to read historical values or Events of one or more Nodes. For
    /// constructed Attribute values whose elements are indexed, such as an array, this Service
    /// allows Clients to read the entire set of indexed values as a composite, to read individual
    /// elements or to read ranges of elements of the composite. Servers may make historical
    /// values available to Clients using this Service, although the historical values themselves
    /// are not visible in the AddressSpace.
    pub fn read(&self, server_state: &mut ServerState, session: &mut Session, request: ReadRequest) -> Result<SupportedMessage, StatusCode> {
        // Read nodes and their attributes
        let timestamps_to_return = request.timestamps_to_return;

        if request.max_age < 0f64 {
            warn!("ReadRequest max age is invalid");
            return Ok(self.service_fault(&request.request_header, BAD_MAX_AGE_INVALID));
        }

        let results = if let Some(ref nodes_to_read) = request.nodes_to_read {
            let address_space = server_state.address_space.lock().unwrap();
            let results = nodes_to_read.iter().map(|node_to_read| {
                Self::read_node_value(session, &address_space, node_to_read, timestamps_to_return)
            }).collect();
            Some(results)
        } else {
            warn!("ReadRequest nothing to do");
            return Ok(self.service_fault(&request.request_header, BAD_NOTHING_TO_DO));
        };

        let diagnostic_infos = None;
        let response = ReadResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results,
            diagnostic_infos,
        };

        trace!("ReadResponse = {:#?}", &response);

        Ok(SupportedMessage::ReadResponse(response))
    }

    fn read_node_value(session: &Session, address_space: &AddressSpace, node_to_read: &ReadValueId, timestamps_to_return: TimestampsToReturn) -> DataValue {
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
                if let Some(attribute) = node.as_node().find_attribute(attribute_id) {
                    let is_readable = Self::is_readable(session, &node);
                    if !is_readable {
                        result_value.status = Some(BAD_NOT_READABLE)
                    } else if !node_to_read.index_range.is_null() {
                        // Index ranges are not supported
                        result_value.status = Some(BAD_NOT_READABLE);
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
                            TimestampsToReturn::Neither => {
                                // Nothing needs to change
                            }
                        }
                    }
                } else {
                    result_value.status = Some(BAD_ATTRIBUTE_ID_INVALID);
                }
            } else {
                warn!("Attribute id {} is invalid", node_to_read.attribute_id);
                result_value.status = Some(BAD_ATTRIBUTE_ID_INVALID);
            }
        } else {
            warn!("Cannot find node id {:?}", node_to_read.node_id);
            result_value.status = Some(BAD_NODE_ID_UNKNOWN);
        }
        result_value
    }

    fn is_readable(_: &Session, node: &NodeType) -> bool {
        // Check for access level, user access level
        if let NodeType::Variable(ref node) = *node {
            if node.access_level() & access_level::CURRENT_READ == 0 {
                return false;
            }
        }
        true
    }

    /// Spec:
    ///
    /// This Service is used to write values to one or more Attributes of one or more Nodes. For
    /// constructed Attribute values whose elements are indexed, such as an array, this Service
    /// allows Clients to write the entire set of indexed values as a composite, to write individual
    /// elements or to write ranges of elements of the composite.
    pub fn write(&self, server_state: &mut ServerState, session: &mut Session, request: WriteRequest) -> Result<SupportedMessage, StatusCode> {
        let results = if let Some(ref nodes_to_write) = request.nodes_to_write {
            let mut address_space = server_state.address_space.lock().unwrap();
            let results = nodes_to_write.iter().map(|node_to_write| {
                Self::write_node_value(session, &mut address_space, node_to_write)
            }).collect();
            Some(results)
        } else {
            return Ok(self.service_fault(&request.request_header, BAD_NOTHING_TO_DO));
        };

        let diagnostic_infos = None;
        let response = WriteResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results,
            diagnostic_infos,
        };

        Ok(SupportedMessage::WriteResponse(response))
    }

    fn write_node_value(session: &Session, address_space: &mut AddressSpace, node_to_write: &WriteValue) -> StatusCode {
        if let Some(node) = address_space.find_node_mut(&node_to_write.node_id) {
            if let Ok(attribute_id) = AttributeId::from_u32(node_to_write.attribute_id) {
                let is_writable = Self::is_writable(session, &node, attribute_id);
                if !is_writable {
                    BAD_NOT_WRITABLE
                } else if !node_to_write.index_range.is_null() {
                    // Index ranges are not supported
                    BAD_WRITE_NOT_SUPPORTED
                } else {
                    let node = node.as_mut_node();
                    let result = node.set_attribute(attribute_id, node_to_write.value.clone());
                    if result.is_err() {
                        result.unwrap_err()
                    } else {
                        GOOD
                    }
                }
            } else {
                warn!("Attribute id {} is invalid", node_to_write.attribute_id);
                BAD_ATTRIBUTE_ID_INVALID
            }
        } else {
            warn!("Cannot find node id {:?}", node_to_write.node_id);
            BAD_NODE_ID_UNKNOWN
        }
    }

    fn is_writable(_: &Session, node: &NodeType, attribute_id: AttributeId) -> bool {
        use opcua_types::write_mask;

        if let Some(write_mask) = node.as_node().write_mask() {
            match attribute_id {
                AttributeId::Value => {
                    // Variable types test writability using the access level
                    if let NodeType::Variable(ref node) = *node {
                        node.access_level() & access_level::CURRENT_WRITE != 0
                    } else {
                        write_mask & write_mask::VALUE_FOR_VARIABLE_TYPE != 0
                    }
                }
                AttributeId::NodeId => write_mask & write_mask::NODE_ID != 0,
                AttributeId::NodeClass => write_mask & write_mask::NODE_CLASS != 0,
                AttributeId::BrowseName => write_mask & write_mask::BROWSE_NAME != 0,
                AttributeId::DisplayName => write_mask & write_mask::DISPLAY_NAME != 0,
                AttributeId::Description => write_mask & write_mask::DESCRIPTION != 0,
                AttributeId::WriteMask => write_mask & write_mask::WRITE_MASK != 0,
                AttributeId::UserWriteMask => write_mask & write_mask::USER_WRITE_MASK != 0,
                AttributeId::IsAbstract => write_mask & write_mask::IS_ABSTRACT != 0,
                AttributeId::Symmetric => write_mask & write_mask::SYMMETRIC != 0,
                AttributeId::InverseName => write_mask & write_mask::INVERSE_NAME != 0,
                AttributeId::ContainsNoLoops => write_mask & write_mask::CONTAINS_NO_LOOPS != 0,
                AttributeId::EventNotifier => write_mask & write_mask::EVENT_NOTIFIER != 0,
                AttributeId::DataType => write_mask & write_mask::DATA_TYPE != 0,
                AttributeId::ValueRank => write_mask & write_mask::VALUE_RANK != 0,
                AttributeId::ArrayDimensions => write_mask & write_mask::ARRAY_DIMENSTIONS != 0,
                AttributeId::AccessLevel => write_mask & write_mask::ACCESS_LEVEL != 0,
                AttributeId::UserAccessLevel => write_mask & write_mask::USER_ACCESS_LEVEL != 0,
                AttributeId::MinimumSamplingInterval => write_mask & write_mask::MINIMUM_SAMPLING_INTERVAL != 0,
                AttributeId::Historizing => write_mask & write_mask::HISTORIZING != 0,
                AttributeId::Executable => write_mask & write_mask::EXECUTABLE != 0,
                AttributeId::UserExecutable => write_mask & write_mask::USER_EXECUTABLE != 0,
            }
        } else {
            true
        }
    }
}
