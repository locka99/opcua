use std::result::Result;

use opcua_core::address_space::*;
use opcua_core::types::*;
use opcua_core::comms::*;
use opcua_core::services::*;

use types::*;
use server::ServerState;

pub struct AttributeService {}

impl AttributeService {
    pub fn new() -> AttributeService {
        AttributeService {}
    }

    pub fn read(&self, server_state: &mut ServerState, _: &mut SessionState, request: &ReadRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("read request {:#?}", request);

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

                let mut value = None;
                let mut status = &GOOD;
                let mut source_timestamp = None;
                let mut source_picoseconds = None;
                let mut server_timestamp = None;
                let mut server_picoseconds = None;

                // Node node found
                if node.is_none() {
                    warn!("Cannot find node id {:?}", node_to_read.node_id);
                    status = &BAD_NODE_ID_UNKNOWN;
                } else {
                    let node = node.unwrap();
                    let attribute_id = AttributeId::from_u32(node_to_read.attribute_id);
                    if attribute_id.is_err() {
                        error!("Attribute id {} is invalid", node_to_read.attribute_id);
                        status = &BAD_ATTRIBUTE_ID_INVALID;
                    } else {
                        let attribute_id = attribute_id.unwrap();
                        let attribute = node.as_node().find_attribute(attribute_id);
                        if attribute.is_none() {
                            status = &BAD_NOT_READABLE;
                        } else {
                            let attribute = attribute.unwrap();
                            value = Some(Box::new(attribute.value.to_variant()));
                            match timestamps_to_return {
                                TimestampsToReturn::Source => {
                                    source_timestamp = Some(attribute.source_timestamp.clone());
                                    source_picoseconds = Some(attribute.source_picoseconds.clone());
                                },
                                TimestampsToReturn::Server => {
                                    server_timestamp = Some(attribute.server_timestamp.clone());
                                    server_picoseconds = Some(attribute.server_picoseconds.clone());
                                },
                                TimestampsToReturn::Both => {
                                    source_timestamp = Some(attribute.source_timestamp.clone());
                                    source_picoseconds = Some(attribute.source_picoseconds.clone());
                                    server_timestamp = Some(attribute.server_timestamp.clone());
                                    server_picoseconds = Some(attribute.server_picoseconds.clone());
                                },
                                TimestampsToReturn::Neither => {
                                    // Nothing needs to change
                                },
                            }
                        }
                    }
                }
                results.push(DataValue {
                    value: value,
                    status: Some(status.clone()),
                    source_timestamp: source_timestamp,
                    source_picoseconds: source_picoseconds,
                    server_timestamp: server_timestamp,
                    server_picoseconds: server_picoseconds,
                });
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
