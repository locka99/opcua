use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use types::*;
use server::ServerState;

pub struct ViewService {}

impl ViewService {
    pub fn new() -> ViewService {
        ViewService {}
    }

    pub fn browse(&self, server_state: &mut ServerState, _: &mut SessionState, request: &BrowseRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("browse {:#?}", request);
        let browse_results = if request.nodes_to_browse.is_some() {
            let nodes_to_browse = request.nodes_to_browse.as_ref().unwrap();
            let mut browse_results: Vec<BrowseResult> = Vec::new();

            // TODO Description of the view to browse

            let address_space = server_state.address_space.lock().unwrap();

            // Nodes to browse
            for node_to_browse in nodes_to_browse {
                let node = address_space.find(&node_to_browse.node_id);
                if node.is_none() {
                    continue;
                }
                let node = node.unwrap();

                // pub node_id: NodeId,
                // pub browse_direction: BrowseDirection,
                // pub reference_type_id: NodeId,
                // pub include_subtypes: Boolean,
                // pub node_class_mask: UInt32,
                // pub result_mask: UInt32,

                let reference = ReferenceDescription {
                    reference_type_id: NodeId::null(),
                    is_forward: false,
                    node_id: ExpandedNodeId::new(&NodeId::null()),
                    browse_name: QualifiedName::new(0, "todo"),
                    display_name: LocalizedText::new("", "todo"),
                    node_class: NodeClass::Object,
                    type_definition: ExpandedNodeId::new(&NodeId::null()),
                };

                // TODO requested_max_references_per_node
                let references = vec![reference];
                let browse_result = BrowseResult {
                    status_code: GOOD.clone(),
                    continuation_point: ByteString::null(),
                    references: Some(references)
                };
            }

            Some(vec![])
        } else {
            return Err(&BAD_NOTHING_TO_DO);
        };
        let response = BrowseResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
            results: browse_results,
            diagnostic_infos: None,
        };
        Ok(SupportedMessage::BrowseResponse(response))
    }
}