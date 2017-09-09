use std::result::Result;
use std::sync::{Arc, Mutex};

use opcua_types::*;

use address_space::address_space::AddressSpace;
use server::ServerState;
use session::Session;
use services::Service;
use continuation_point::BrowseContinuationPoint;

// Bits that control the reference description coming back from browse()

const RESULT_MASK_REFERENCE_TYPE: UInt32 = 1;
const RESULT_MASK_IS_FORWARD: UInt32 = 1 << 1;
const RESULT_MASK_NODE_CLASS: UInt32 = 1 << 2;
const RESULT_MASK_BROWSE_NAME: UInt32 = 1 << 3;
const RESULT_MASK_DISPLAY_NAME: UInt32 = 1 << 4;
const RESULT_MASK_TYPE_DEFINITION: UInt32 = 1 << 5;

pub struct ViewService {}

impl Service for ViewService {}

impl ViewService {
    pub fn new() -> ViewService {
        ViewService {}
    }

    pub fn browse(&self, server_state: &mut ServerState, session: &mut Session, request: BrowseRequest) -> Result<SupportedMessage, StatusCode> {
        let browse_results = if request.nodes_to_browse.is_some() {
            let nodes_to_browse = request.nodes_to_browse.as_ref().unwrap();

            if !request.view.view_id.is_null() {
                // Views are not supported
                info!("Browse request ignored because view was specified (views not supported)");
                return Ok(self.service_fault(&request.request_header, BAD_VIEW_ID_UNKNOWN));
            }

            let address_space = server_state.address_space.lock().unwrap();
            Some(Self::browse_nodes(session, &address_space, nodes_to_browse, request.requested_max_references_per_node as usize))
        } else {
            // Nothing to do
            return Ok(self.service_fault(&request.request_header, BAD_NOTHING_TO_DO));
        };

        let diagnostic_infos = None;
        let response = BrowseResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results: browse_results,
            diagnostic_infos,
        };

        Ok(SupportedMessage::BrowseResponse(response))
    }

    pub fn browse_next(&self, server_state: &mut ServerState, session: &mut Session, request: BrowseNextRequest) -> Result<SupportedMessage, StatusCode> {
        if request.continuation_points.is_none() {
            Ok(self.service_fault(&request.request_header, BAD_NOTHING_TO_DO))
        } else {
            let continuation_points = request.continuation_points.as_ref().unwrap();
            let results = if request.release_continuation_points {
                session.remove_browse_continuation_points(continuation_points);
                None
            } else {
                let address_space = server_state.address_space.lock().unwrap();
                let mut results = Vec::with_capacity(continuation_points.len());
                for continuation_point in continuation_points {
                    // Iterate from the continuation point, assuming it is valid
                    let browse_result = Self::browse_from_continuation_point(session, &address_space, continuation_point);
                    results.push(browse_result);
                }
                Some(results)
            };

            let diagnostic_infos = None;
            let response = BrowseNextResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results,
                diagnostic_infos,
            };
            Ok(SupportedMessage::BrowseNextResponse(response))
        }
    }

    pub fn translate_browse_paths_to_node_ids(&self, server_state: &mut ServerState, _: &mut Session, request: TranslateBrowsePathsToNodeIdsRequest) -> Result<SupportedMessage, StatusCode> {
        trace!("TranslateBrowsePathsToNodeIdsRequest = {:?}", &request);

        if request.browse_paths.is_none() {
            return Ok(self.service_fault(&request.request_header, BAD_NOTHING_TO_DO));
        }
        let browse_paths = request.browse_paths.unwrap();
        if browse_paths.is_empty() {
            return Ok(self.service_fault(&request.request_header, BAD_NOTHING_TO_DO));
        }

        let mut results: Vec<BrowsePathResult> = Vec::with_capacity(browse_paths.len());

        let address_space = server_state.address_space.lock().unwrap();
        for browse_path in browse_paths.iter() {
            let node_id = browse_path.starting_node.clone();
            let browse_result = if browse_path.relative_path.elements.is_none() {
                BrowsePathResult {
                    status_code: BAD_NOTHING_TO_DO,
                    targets: None,
                }
            } else {
                // Starting from the node_id, find paths
                let result = address_space.find_nodes_relative_path(&node_id, &browse_path.relative_path);
                if result.is_err() {
                    BrowsePathResult {
                        status_code: result.unwrap_err(),
                        targets: None,
                    }
                } else {
                    let result = result.unwrap();
                    let targets = if !results.is_empty() {
                        use std::u32;
                        let mut targets = Vec::with_capacity(result.len());
                        for node_id in &result {
                            targets.push(BrowsePathTarget {
                                target_id: ExpandedNodeId::new(node_id),
                                remaining_path_index: u32::MAX as UInt32,
                            });
                        }
                        Some(targets)
                    } else {
                        None
                    };
                    BrowsePathResult {
                        status_code: GOOD,
                        targets,
                    }
                }
            };
            results.push(browse_result);
        }

        let response = TranslateBrowsePathsToNodeIdsResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results: Some(results),
            diagnostic_infos: None,
        };

        Ok(SupportedMessage::TranslateBrowsePathsToNodeIdsResponse(response))
    }

    fn browse_nodes(session: &mut Session, address_space: &AddressSpace, nodes_to_browse: &[BrowseDescription], max_references_per_node: usize) -> Vec<BrowseResult> {
        let mut browse_results: Vec<BrowseResult> = Vec::with_capacity(nodes_to_browse.len());
        for node_to_browse in nodes_to_browse {
            let browse_result = Self::browse_node(session, &address_space, 0, node_to_browse, max_references_per_node);
            browse_results.push(if let Ok(browse_result) = browse_result {
                browse_result
            } else {
                BrowseResult {
                    status_code: browse_result.unwrap_err(),
                    continuation_point: ByteString::null(),
                    references: None
                }
            });
        }
        browse_results
    }

    fn browse_node(session: &mut Session, address_space: &AddressSpace, starting_index: usize, node_to_browse: &BrowseDescription, max_references_per_node: usize) -> Result<BrowseResult, StatusCode> {
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
        let mut reference_descriptions: Vec<ReferenceDescription> = Vec::with_capacity(max_references_per_node);
        for (idx, reference) in references.iter().enumerate() {
            if idx < starting_index {
                continue;
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
                reference_type_id,
                is_forward,
                node_class: target_node_class,
                browse_name,
                display_name,
                type_definition,
            };
            reference_descriptions.push(reference_description);
        }

        Ok(Self::reference_description_to_browse_result(session, address_space, &reference_descriptions, 0, max_references_per_node))
    }

    fn browse_from_continuation_point(session: &mut Session, address_space: &AddressSpace, continuation_point: &ByteString) -> BrowseResult {
        // Find the continuation point in the session
        session.remove_expired_browse_continuation_points(address_space);
        if let Some(continuation_point) = session.find_browse_continuation_point(continuation_point) {
            let reference_descriptions = continuation_point.reference_descriptions.lock().unwrap();
            // Use the existing result. This may result in another continuation point being created
            Self::reference_description_to_browse_result(session, address_space, &reference_descriptions, continuation_point.starting_index, continuation_point.max_references_per_node)
        }
        else {
            // Not valid or missing
            BrowseResult {
                status_code: BAD_CONTINUATION_POINT_INVALID,
                continuation_point: ByteString::null(),
                references: None,
            }
        }
    }

    fn reference_description_to_browse_result(session: &mut Session, address_space: &AddressSpace, reference_descriptions: &[ReferenceDescription], starting_index: usize, max_references_per_node: usize) -> BrowseResult {
        let references_remaining = reference_descriptions.len() - starting_index;
        let (reference_descriptions, continuation_point) = if max_references_per_node > 0 && references_remaining > max_references_per_node {
            // There is too many results for a single browse result, so only a result will be used
            let ending_index = starting_index + max_references_per_node;
            let reference_descriptions_slice = reference_descriptions[starting_index..ending_index].to_vec();

            // TODO it is wasteful to create a new reference_descriptions vec if the caller to this fn
            // already has a ref counted reference_descriptions. We could clone the Arc if the fn could
            // be factored to allow for that

            // Create a continuation point for the remainder of the result. The point will hold the entire result
            let continuation_point = ByteString::random(6);
            session.add_browse_continuation_point(BrowseContinuationPoint {
                id: continuation_point.clone(),
                address_space_last_modified: address_space.last_modified.clone(),
                max_references_per_node,
                starting_index: ending_index,
                reference_descriptions: Arc::new(Mutex::new(reference_descriptions.to_vec()))
            });
            (reference_descriptions_slice, continuation_point)
        }
        else {
            let reference_descriptions_slice = reference_descriptions[starting_index..].to_vec();
            (reference_descriptions_slice, ByteString::null())
        };
        BrowseResult {
            status_code: GOOD,
            continuation_point,
            references: Some(reference_descriptions)
        }
    }

}