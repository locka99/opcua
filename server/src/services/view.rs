use std::result::Result;

use opcua_core::address_space::*;
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
                let references = ViewService::reference_descriptions(&address_space, node_to_browse);
                if references.is_err() {
                    continue;
                }
                let browse_result = BrowseResult {
                    status_code: GOOD.clone(),
                    continuation_point: ByteString::null(),
                    references: Some(references.unwrap())
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

    /// Test if the node matches the class mask
    fn node_matches_class_mask(node: &NodeType, node_class_mask: UInt32) -> bool {
        match node {
            &NodeType::Object(_) => { node_class_mask & 1 << 0 != 0 },
            &NodeType::Variable(_) => { node_class_mask & 1 << 1 != 0 },
            &NodeType::Method(_) => { node_class_mask & 1 << 2 != 0 },
            &NodeType::ObjectType(_) => { node_class_mask & 1 << 3 != 0 },
            &NodeType::VariableType(_) => { node_class_mask & 1 << 4 != 0 },
            &NodeType::ReferenceType(_) => { node_class_mask & 1 << 5 != 0 },
            // &NodeType::DataType(_) => {node_class_mask & 1 << 6 != 0},
            &NodeType::View(_) => { node_class_mask & 1 << 7 != 0 },
        }
    }

    fn reference_descriptions(address_space: &AddressSpace, node_to_browse: &BrowseDescription) -> Result<Vec<ReferenceDescription>, ()> {
        let source_node = address_space.find(&node_to_browse.node_id);
        if source_node.is_none() {
            return Err(());
        }
        let source_node = source_node.unwrap();

        match node_to_browse.browse_direction {
            BrowseDirection::Forward => {
                for reference in source_node.as_node().references() {}
            }
            BrowseDirection::Inverse => {
                // TODO
            }
            BrowseDirection::Both => {}
            // TODO
        }

        if !node_to_browse.reference_type_id.is_null() {
            // TODO Only reference type should be returned
            // TODO test to see if that includes subtupes node_to_browser.include_subtypes
        }


        let mut reference_descriptions: Vec<ReferenceDescription> = Vec::new();
        if ViewService::node_matches_class_mask(source_node, node_to_browse.node_class_mask) {
            let source_node = source_node.as_node();
            for reference in source_node.references() {
                let result_mask = node_to_browse.result_mask;
                /* let reference_type_id = if result_mask & 1 << 0 != 0 {} else {
                    NodeId::null()
                };
                let is_forward = if result_mask & 1 << 1 != 0 {
                    true
                }
                else {
                    false
                }; */


                let reference_description = ReferenceDescription {
                    reference_type_id: NodeId::null(),
                    is_forward: false,
                    node_class: NodeClass::Object,
                    node_id: ExpandedNodeId::new(&NodeId::null()),
                    browse_name: QualifiedName::new(0, "todo"),
                    display_name: LocalizedText::new("", "todo"),
                    type_definition: ExpandedNodeId::new(&NodeId::null()),
                };

                // TODO requested_max_references_per_node
                reference_descriptions.push(reference_description);
            }
        }

        Ok(reference_descriptions)
    }
}