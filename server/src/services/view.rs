use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use address_space::*;
use server::ServerState;
use session::SessionState;

pub struct ViewService {}

// Bits that control the reference description coming back from browse()

const RESULT_MASK_REFERENCE_TYPE: UInt32 = 1 << 0;
const RESULT_MASK_IS_FORWARD: UInt32 = 1 << 1;
const RESULT_MASK_NODE_CLASS: UInt32 = 1 << 2;
const RESULT_MASK_BROWSE_NAME: UInt32 = 1 << 3;
const RESULT_MASK_DISPLAY_NAME: UInt32 = 1 << 4;
const RESULT_MASK_TYPE_DEFINITION: UInt32 = 1 << 5;

impl ViewService {
    pub fn new() -> ViewService {
        ViewService {}
    }

    pub fn browse(&self, server_state: &mut ServerState, _: &mut SessionState, request: BrowseRequest) -> Result<SupportedMessage, StatusCode> {
        let service_status = GOOD;

        let browse_results = if request.nodes_to_browse.is_some() {
            let nodes_to_browse = request.nodes_to_browse.as_ref().unwrap();
            let mut browse_results: Vec<BrowseResult> = Vec::new();

            if !request.view.view_id.is_null() {
                // Views are not supported
                info!("Browse request ignored because view was specified (views not supported)");
                return Ok(SupportedMessage::BrowseResponse(BrowseResponse {
                    response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, BAD_VIEW_ID_UNKNOWN),
                    results: None,
                    diagnostic_infos: None,
                }));
            }

            let address_space = server_state.address_space.lock().unwrap();

            // Nodes to browse
            for node_to_browse in nodes_to_browse {
                let references = ViewService::reference_descriptions(&address_space, node_to_browse, request.requested_max_references_per_node);
                let browse_result = if references.is_err() {
                    BrowseResult {
                        status_code: references.unwrap_err().clone(),
                        continuation_point: ByteString::null(),
                        references: None
                    }
                } else {
                    BrowseResult {
                        status_code: GOOD,
                        continuation_point: ByteString::null(),
                        references: Some(references.unwrap())
                    }
                };
                browse_results.push(browse_result);
            }

            Some(browse_results)
        } else {
            // Nothing to do
            return Ok(SupportedMessage::BrowseResponse(BrowseResponse {
                response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, BAD_NOTHING_TO_DO),
                results: None,
                diagnostic_infos: None,
            }));
        };

        let response = BrowseResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: browse_results,
            diagnostic_infos: None,
        };

        Ok(SupportedMessage::BrowseResponse(response))
    }

    pub fn browse_next(&self, _: &mut ServerState, _: &mut SessionState, request: BrowseNextRequest) -> Result<SupportedMessage, StatusCode> {
        // BrowseNext does nothing
        let service_status = BAD_NOTHING_TO_DO;
        let response = BrowseNextResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: None,
            diagnostic_infos: None,
        };
        Ok(SupportedMessage::BrowseNextResponse(response))
    }

    pub fn translate_browse_paths_to_node_ids(&self, server_state: &mut ServerState, _: &mut SessionState, request: TranslateBrowsePathsToNodeIdsRequest) -> Result<SupportedMessage, StatusCode> {
        let (service_status, results) = (BAD_NOTHING_TO_DO, None); /* if request.browse_paths.is_none() {
            let browse_paths = request.browse_paths.as_ref().unwrap();

            let mut results: Vec<BrowsePathResult> = Vec::with_capacity(browse_paths.len());
            if browse_paths.is_empty() {
                (BAD_NOTHING_TO_DO, None)
            } else {
                let address_space = server_state.address_space.lock().unwrap();
                for browse_path in browse_paths.iter() {
                    let mut current_node = browse_path.starting_node.clone();
                    let browse_result = if address_space.find_node(&current_node).is_none() {
                        BrowsePathResult {
                            status_code: BAD_NODE_ID_UNKNOWN,
                            targets: None,
                        }
                    } else if browse_path.relative_path.elements.is_none() {
                        BrowsePathResult {
                            status_code: BAD_NOTHING_TO_DO,
                            targets: None,
                        }
                    } else {
                        // Starting from the node_id...
                        // Can we find the first node
                        let elements = browse_path.relative_path.elements.as_ref().unwrap();
                        if elements.is_empty() {
                            BrowsePathResult {
                                status_code: BAD_NOTHING_TO_DO,
                                targets: None,
                            }
                        } else {
                            // Traverse the relative path elements
                            let target_results: Vec<BrowsePathTarget> = Vec::with_capacity(elements.len());
                            for element in elements.iter() {
                                //                               target_results.push(BrowsePathResult {
                                //                                   status_code: (),
                                //                                    targets: (),
                                //                                });
                                current_node = target_node;
                            }
                            BrowsePathResult {
                                status_code: GOOD,
                                targets: Some(target_results)
                            }
                        };
                        results.push(browse_result);
                    };
                }
                (GOOD, Some(results))
            }
        }; */

        debug!("TranslateBrowsePathsToNodeIdsRequest = {:#?}", request);

        let response = TranslateBrowsePathsToNodeIdsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None,
        };
        Ok(SupportedMessage::TranslateBrowsePathsToNodeIdsResponse(response))
    }

    fn reference_descriptions(address_space: &AddressSpace, node_to_browse: &BrowseDescription, max_references_per_node: UInt32) -> Result<Vec<ReferenceDescription>, StatusCode> {
        // Node must exist or there will be no references
        if node_to_browse.node_id.is_null() || !address_space.node_exists(&node_to_browse.node_id) {
            return Err(BAD_NODE_ID_UNKNOWN);
        }

        // Request may wish to filter by a kind of reference
        let reference_type_id = if node_to_browse.reference_type_id.is_null() {
            None
        } else {
            if let Ok(reference_type_id) = node_to_browse.reference_type_id.as_reference_type_id() {
                Some((reference_type_id, node_to_browse.include_subtypes))
            } else {
                None
            }
        };

        // Fetch the references to / from the given node to browse

        let (references, inverse_ref_idx) = address_space.find_references_by_direction(&node_to_browse.node_id, node_to_browse.browse_direction, reference_type_id);

        let result_mask = node_to_browse.result_mask;
        let node_class_mask = node_to_browse.node_class_mask;

        // Construct descriptions for each reference
        let mut reference_descriptions: Vec<ReferenceDescription> = Vec::new();
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
            let target_node_class = target_node.node_class();

            // Skip target nodes not required by the mask
            if node_class_mask != 0 && node_class_mask & (target_node_class as UInt32) == 0 {
                continue;
            }

            // Prepare the values to put into the struct according to the result mask
            let reference_type_id = if result_mask & RESULT_MASK_REFERENCE_TYPE != 0 {
                reference.reference_type_id.as_node_id()
            } else {
                NodeId::null()
            };
            let is_forward = if result_mask & RESULT_MASK_IS_FORWARD != 0 {
                idx < inverse_ref_idx
            } else {
                true
            };

            let target_node_class = if result_mask & RESULT_MASK_NODE_CLASS != 0 {
                target_node_class
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
                // Type definition NodeId of the TargetNode. Type definitions are only available
                // for the NodeClasses Object and Variable. For all other NodeClasses a null NodeId
                // shall be returned.
                match target_node_class {
                    NodeClass::Object | NodeClass::Variable => {
                        let type_defs = address_space.find_references_from(&target_node.node_id(), Some((ReferenceTypeId::HasTypeDefinition, false)));
                        if let Some(type_defs) = type_defs {
                            ExpandedNodeId::new(&type_defs[0].node_id)
                        } else {
                            ExpandedNodeId::null()
                        }
                    }
                    _ => {
                        ExpandedNodeId::null()
                    }
                }
            } else {
                ExpandedNodeId::null()
            };

            let reference_description = ReferenceDescription {
                node_id: ExpandedNodeId::new(&target_node_id),
                reference_type_id: reference_type_id,
                is_forward: is_forward,
                node_class: target_node_class,
                browse_name: browse_name,
                display_name: display_name,
                type_definition: type_definition,
            };

            reference_descriptions.push(reference_description);
        }

        Ok(reference_descriptions)
    }
}