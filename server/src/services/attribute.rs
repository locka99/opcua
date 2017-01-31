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

        // pub max_age: Double,
        // pub timestamps_to_return: TimestampsToReturn,

        let results = if request.nodes_to_read.is_some() {
            let mut results: Vec<DataValue> = Vec::new();

            let nodes_to_read = request.nodes_to_read.as_ref().unwrap();
            for node_to_read in nodes_to_read {
                //pub node_id: NodeId,
                //pub attribute_id: UInt32,
                //pub index_range: UAString,
                //pub data_encoding: QualifiedName,

                let node = address_space.find_node(&node_to_read.node_id);
                if node.is_none() {
                    warn!("Cannot find node id {:?}", node_to_read.node_id);
                    continue;
                }

                let node = node.unwrap();

                let attribute_id = AttributeId::from_u32(node_to_read.attribute_id);
                if attribute_id.is_err() {
                    error!("Attribute id {} is invalid",node_to_read.attribute_id);
                    continue;
                }
                let attribute_id = attribute_id.unwrap();
                let attribute = node.as_node().find_attribute(attribute_id);

                let value = None;
                let status = None;

                let source_timestamp;
                let source_picoseconds;
                let server_timestamp;
                let server_picoseconds;
                match timestamps_to_return {
                    TimestampsToReturn::Source => {
                        source_timestamp = None; // TODO
                        source_picoseconds = None; // TODO
                        server_timestamp = None;
                        server_picoseconds = None;
                    },
                    TimestampsToReturn::Server => {
                        source_timestamp = None;
                        source_picoseconds = None;
                        server_timestamp = None; // TODO
                        server_picoseconds = None; // TODO
                    },
                    TimestampsToReturn::Both => {
                        source_timestamp = None; // TODO
                        source_picoseconds = None; // TODO
                        server_timestamp = None; // TODO
                        server_picoseconds = None; // TODO
                    },
                    TimestampsToReturn::Neither => {
                        source_timestamp = None;
                        source_picoseconds = None;
                        server_timestamp = None;
                        server_picoseconds = None;
                    },
                }
                results.push(DataValue {
                    value: value,
                    status: status,
                    source_timestamp: source_timestamp,
                    source_pico_seconds: source_picoseconds,
                    server_timestamp: server_timestamp,
                    server_pico_seconds: server_picoseconds,
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
