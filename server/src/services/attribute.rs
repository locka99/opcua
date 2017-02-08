use std::result::Result;

use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::services::*;

use types::*;
use address_space::*;
use server::ServerState;

pub struct AttributeService {}

impl AttributeService {
    pub fn new() -> AttributeService {
        AttributeService {}
    }

    pub fn read(&self, server_state: &mut ServerState, _: &mut SessionState, request: &ReadRequest) -> Result<SupportedMessage, &'static StatusCode> {
        // Read nodes and their attributes
        let timestamps_to_return = request.timestamps_to_return;
        let address_space = server_state.address_space.lock().unwrap();

        if request.max_age < 0f64 {
            return Err(&BAD_MAX_AGE_INVALID);
        }

        let results = if request.nodes_to_read.is_some() {
            let nodes_to_read = request.nodes_to_read.as_ref().unwrap();

            let mut results: Vec<DataValue> = Vec::with_capacity(nodes_to_read.len());
            for node_to_read in nodes_to_read {
                let node = address_space.find_node(&node_to_read.node_id);

                let mut result_value = DataValue {
                    value: None,
                    status: None,
                    source_timestamp: None,
                    source_picoseconds: None,
                    server_timestamp: None,
                    server_picoseconds: None,
                };

                // Node node found
                if node.is_some() {
                    let node = node.unwrap();
                    let attribute_id = AttributeId::from_u32(node_to_read.attribute_id);
                    if attribute_id.is_ok() {
                        let attribute_id = attribute_id.unwrap();
                        let attribute = node.as_node().find_attribute(attribute_id);
                        if attribute.is_some() {
                            let attribute = attribute.unwrap();
                            // Result value is clone from the attribute
                            result_value.value = attribute.value.clone();
                            result_value.status = attribute.status.clone();
                            match timestamps_to_return {
                                TimestampsToReturn::Source => {
                                    result_value.source_timestamp = attribute.source_timestamp.clone();
                                    result_value.source_picoseconds = attribute.source_picoseconds.clone();
                                },
                                TimestampsToReturn::Server => {
                                    result_value.server_timestamp = attribute.server_timestamp.clone();
                                    result_value.server_picoseconds = attribute.server_picoseconds.clone();
                                },
                                TimestampsToReturn::Both => {
                                    result_value.source_timestamp = attribute.source_timestamp.clone();
                                    result_value.source_picoseconds = attribute.source_picoseconds.clone();
                                    result_value.server_timestamp = attribute.server_timestamp.clone();
                                    result_value.server_picoseconds = attribute.server_picoseconds.clone();
                                },
                                TimestampsToReturn::Neither => {
                                    // Nothing needs to change
                                },
                            }
                        } else {
                            result_value.status = Some(BAD_NOT_READABLE.clone());
                        }
                    } else {
                        error!("Attribute id {} is invalid", node_to_read.attribute_id);
                        result_value.status = Some(BAD_ATTRIBUTE_ID_INVALID.clone());
                    }
                } else {
                    warn!("Cannot find node id {:?}", node_to_read.node_id);
                    result_value.status = Some(BAD_NODE_ID_UNKNOWN.clone());
                }
                results.push(result_value);
            }
            Some(results)
        } else {
            None
        };
        let diagnostic_infos = None;

        let response = ReadResponse {
            response_header: ResponseHeader::new(&DateTime::now(), &request.request_header),
            results: results,
            diagnostic_infos: diagnostic_infos,
        };

        Ok(SupportedMessage::ReadResponse(response))
    }
}
