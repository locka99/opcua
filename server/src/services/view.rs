use std::result::Result;

use opcua_core::address_space::*;
use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use types::*;
use server::ServerState;

pub struct ViewService {}

// Bits that control the reference description coming back from browse()

/// 0 - reference_type
const RESULT_MASK_REFERENCE_TYPE: UInt32 = 1 << 0;
/// 1 isforward
const RESULT_MASK_IS_FORWARD: UInt32 = 1 << 1;
/// 2 nodeclass
const RESULT_MASK_NODE_CLASS: UInt32 = 1 << 2;
/// 3 browsename
const RESULT_MASK_BROWSE_NAME: UInt32 = 1 << 3;
/// 4 displayname
const RESULT_MASK_DISPLAY_NAME: UInt32 = 1 << 4;
/// 5 typedefinition
const RESULT_MASK_TYPE_DEFINITION: UInt32 = 1 << 5;


impl ViewService {
    pub fn new() -> ViewService {
        ViewService {}
    }

    pub fn browse(&self, server_state: &mut ServerState, _: &mut SessionState, request: &BrowseRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("browse {:#?}", request);
        let browse_results = if request.nodes_to_browse.is_some() {
            let nodes_to_browse = request.nodes_to_browse.as_ref().unwrap();
            let mut browse_results: Vec<BrowseResult> = Vec::new();

            if !request.view.view_id.is_null() {
                // Views are not supported
                return Ok(SupportedMessage::BrowseResponse(BrowseResponse {
                    response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, &BAD_VIEW_ID_UNKNOWN),
                    results: None,
                    diagnostic_infos: None,
                }));
            }

            let address_space = server_state.address_space.lock().unwrap();

            // Nodes to browse
            for node_to_browse in nodes_to_browse {
                let references = ViewService::reference_descriptions(&address_space, node_to_browse, request.requested_max_references_per_node);
                if references.is_err() {
                    continue;
                }
                browse_results.push(BrowseResult {
                    status_code: GOOD.clone(),
                    continuation_point: ByteString::null(),
                    references: Some(references.unwrap())
                });
            }

            Some(browse_results)
        } else {
            // Nothing to do
            return Ok(SupportedMessage::BrowseResponse(BrowseResponse {
                response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, &BAD_NOTHING_TO_DO),
                results: None,
                diagnostic_infos: None,
            }));
        };

        let response = BrowseResponse {
            response_header: ResponseHeader::new(&DateTime::now(), &request.request_header),
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
            &NodeType::DataType(_) => {node_class_mask & 1 << 6 != 0},
            &NodeType::View(_) => { node_class_mask & 1 << 7 != 0 },
        }
    }

    fn reference_descriptions(address_space: &AddressSpace, node_to_browse: &BrowseDescription, max_references_per_node: UInt32) -> Result<Vec<ReferenceDescription>, ()> {
        let source_node = address_space.find_node(&node_to_browse.node_id);
        if source_node.is_none() {
            return Err(());
        }
        let source_node = source_node.unwrap();

        // Request may wish to filter by a kind of reference
        let reference_type_id = if node_to_browse.reference_type_id.is_null() {
            None
        } else {
            let reference_type_id = node_to_browse.reference_type_id.as_reference_type_id();
            if reference_type_id.is_ok() {
                Some(reference_type_id.unwrap())
            }
            else {
                None
            }
        };

        // Fetch the references to / from the given node to browse
        let mut references = Vec::new();
        let inverse_ref_idx;
        match node_to_browse.browse_direction {
            BrowseDirection::Forward => {
                let forward_references = address_space.find_references_from(&node_to_browse.node_id, reference_type_id);
                if forward_references.is_some() {
                    references.append(&mut forward_references.unwrap());
                }
                inverse_ref_idx = references.len();
            }
            BrowseDirection::Inverse => {
                inverse_ref_idx = 0;
                let inverse_references = address_space.find_references_to(&node_to_browse.node_id, reference_type_id);
                if inverse_references.is_some() {
                    references.append(&mut inverse_references.unwrap());
                }
            }
            BrowseDirection::Both => {
                let forward_references = address_space.find_references_from(&node_to_browse.node_id, reference_type_id);
                if forward_references.is_some() {
                    references.append(&mut forward_references.unwrap());
                }
                inverse_ref_idx = references.len();
                let inverse_references = address_space.find_references_to(&node_to_browse.node_id, reference_type_id);
                if inverse_references.is_some() {
                    references.append(&mut inverse_references.unwrap());
                }
            }
        }

        let result_mask = node_to_browse.result_mask;

        // Construct descriptions for each reference
        let mut reference_descriptions: Vec<ReferenceDescription> = Vec::new();
        if ViewService::node_matches_class_mask(source_node, node_to_browse.node_class_mask) {
            let source_node = source_node.as_node();
            for (idx, reference) in references.iter().enumerate() {
                if reference_descriptions.len() > max_references_per_node as usize {
                    break;
                }

                let target_node_id = reference.node_id.clone();
                if target_node_id.is_null() {
                    continue;
                }
                let target_node = address_space.find_node(&target_node_id);
                if target_node.is_none() {
                    continue;
                }

                let target_node = target_node.unwrap().as_node();

                // Prepare the values to put into the struct according to the result mask
                let reference_type_id = if result_mask & RESULT_MASK_REFERENCE_TYPE != 0 {
                    NodeId::from_reference_type_id(reference.reference_type_id)
                } else {
                    NodeId::null()
                };
                let is_forward = if result_mask & RESULT_MASK_IS_FORWARD != 0 {
                    idx < inverse_ref_idx
                } else {
                    true
                };
                let node_class = if result_mask & RESULT_MASK_NODE_CLASS != 0 {
                    target_node.node_class()
                } else {
                    NodeClass::Unspecified
                };
                let browse_name = if result_mask & RESULT_MASK_BROWSE_NAME != 0 {
                    target_node.browse_name().clone()
                } else {
                    QualifiedName::null()
                };
                let display_name = if result_mask & RESULT_MASK_DISPLAY_NAME != 0 {
                    target_node.display_name().clone()
                } else {
                    LocalizedText::null()
                };
                let type_definition = if result_mask & RESULT_MASK_TYPE_DEFINITION != 0 {
                    // TODO
                    // Type definition NodeId of the TargetNode. Type definitions are only available
                    // for the NodeClasses Object and Variable. For all other NodeClasses a null NodeId
                    // shall be returned.
                    ExpandedNodeId::null()
                } else {
                    ExpandedNodeId::null()
                };

                let reference_description = ReferenceDescription {
                    node_id: ExpandedNodeId::new(&target_node_id),
                    reference_type_id: reference_type_id,
                    is_forward: is_forward,
                    node_class: node_class,
                    browse_name: browse_name,
                    display_name: display_name,
                    type_definition: type_definition,
                };

                reference_descriptions.push(reference_description);
            }
        }

        Ok(reference_descriptions)
    }
}