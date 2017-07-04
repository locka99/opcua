use std::result::Result;

use opcua_types::*;
use opcua_core::comms::*;

use server::ServerState;
use session::Session;

pub struct AttributeService {}

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
    pub fn read(&self, server_state: &mut ServerState, _: &mut Session, request: ReadRequest) -> Result<SupportedMessage, StatusCode> {
        let mut service_status = GOOD;

        // Read nodes and their attributes
        let timestamps_to_return = request.timestamps_to_return;

        if request.max_age < 0f64 {
            return Err(BAD_MAX_AGE_INVALID);
        }

        let results = if let Some(ref nodes_to_read) = request.nodes_to_read {
            let mut results: Vec<DataValue> = Vec::with_capacity(nodes_to_read.len());

            let address_space = server_state.address_space.lock().unwrap();

            for node_to_read in nodes_to_read {
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
                            if !node_to_read.index_range.is_null() {
                                // Index ranges are not supported
                                result_value.status = Some(BAD_NOT_READABLE);
                            } else {
                                // Result value is clone from the attribute
                                result_value.value = attribute.value.clone();
                                result_value.status = attribute.status.clone();
                                match timestamps_to_return {
                                    TimestampsToReturn::Source => {
                                        result_value.source_timestamp = attribute.source_timestamp.clone();
                                        result_value.source_picoseconds = attribute.source_picoseconds.clone();
                                    }
                                    TimestampsToReturn::Server => {
                                        result_value.server_timestamp = attribute.server_timestamp.clone();
                                        result_value.server_picoseconds = attribute.server_picoseconds.clone();
                                    }
                                    TimestampsToReturn::Both => {
                                        result_value.source_timestamp = attribute.source_timestamp.clone();
                                        result_value.source_picoseconds = attribute.source_picoseconds.clone();
                                        result_value.server_timestamp = attribute.server_timestamp.clone();
                                        result_value.server_picoseconds = attribute.server_picoseconds.clone();
                                    }
                                    TimestampsToReturn::Neither => {
                                        // Nothing needs to change
                                    }
                                }
                            }
                        } else {
                            result_value.status = Some(BAD_NOT_READABLE);
                        }
                    } else {
                        warn!("Attribute id {} is invalid", node_to_read.attribute_id);
                        result_value.status = Some(BAD_ATTRIBUTE_ID_INVALID);
                    }
                } else {
                    warn!("Cannot find node id {:?}", node_to_read.node_id);
                    result_value.status = Some(BAD_NODE_ID_UNKNOWN);
                }
                results.push(result_value);
            }
            Some(results)
        } else {
            service_status = BAD_NOTHING_TO_DO;
            None
        };

        let diagnostic_infos = None;
        let response = ReadResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: diagnostic_infos,
        };

        Ok(SupportedMessage::ReadResponse(response))
    }

    /// Spec:
    ///
    /// This Service is used to write values to one or more Attributes of one or more Nodes. For
    /// constructed Attribute values whose elements are indexed, such as an array, this Service
    /// allows Clients to write the entire set of indexed values as a composite, to write individual
    /// elements or to write ranges of elements of the composite.
    pub fn write(&self, server_state: &mut ServerState, _: &mut Session, request: WriteRequest) -> Result<SupportedMessage, StatusCode> {
        let mut service_status = GOOD;
        let results = if let Some(ref nodes_to_write) = request.nodes_to_write {
            let mut results: Vec<StatusCode> = Vec::with_capacity(nodes_to_write.len());

            let address_space = server_state.address_space.lock().unwrap();

            for node_to_write in nodes_to_write {
                if let Some(node) = address_space.find_node(&node_to_write.node_id) {
                    if let Ok(attribute_id) = AttributeId::from_u32(node_to_write.attribute_id) {
                        let write_result;
                        // Index ranges are not supported
                        if !node_to_write.index_range.is_null() {
                            write_result = BAD_WRITE_NOT_SUPPORTED;
                        } else if let Some(_) = node.as_node().find_attribute(attribute_id) {
                            // TODO implement write, checking masks to see if the action is allowed
                            write_result = BAD_WRITE_NOT_SUPPORTED;
                        } else {
                            write_result = BAD_WRITE_NOT_SUPPORTED;
                        }
                        results.push(write_result);
                    } else {
                        warn!("Attribute id {} is invalid", node_to_write.attribute_id);
                        results.push(BAD_ATTRIBUTE_ID_INVALID);
                    }
                } else {
                    warn!("Cannot find node id {:?}", node_to_write.node_id);
                    results.push(BAD_NODE_ID_UNKNOWN);
                }
            }
            Some(results)
        } else {
            service_status = BAD_NOTHING_TO_DO;
            None
        };

        let diagnostic_infos = None;
        let response = WriteResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: diagnostic_infos,
        };

        Ok(SupportedMessage::WriteResponse(response))
    }
}
