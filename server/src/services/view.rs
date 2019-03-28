use std::result::Result;
use std::sync::{Arc, Mutex};

use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::node_ids::ReferenceTypeId;
use opcua_types::service_types::*;

use crate::{
    address_space::{AddressSpace, relative_path},
    session::Session,
    services::Service,
    continuation_point::BrowseContinuationPoint,
};

// Bits that control the reference description coming back from browse()

bitflags! {
    pub struct BrowseDescriptionResultMask: u32 {
        const RESULT_MASK_REFERENCE_TYPE = 1;
        const RESULT_MASK_IS_FORWARD = 1 << 1;
        const RESULT_MASK_NODE_CLASS = 1 << 2;
        const RESULT_MASK_BROWSE_NAME = 1 << 3;
        const RESULT_MASK_DISPLAY_NAME = 1 << 4;
        const RESULT_MASK_TYPE_DEFINITION = 1 << 5;
    }
}

/// The view service. Allows the client to browse the address space of the server.
pub(crate) struct ViewService;

impl Service for ViewService {}

impl ViewService {
    pub fn new() -> ViewService {
        ViewService {}
    }

    pub fn browse(&self, session: &mut Session, address_space: &AddressSpace, request: &BrowseRequest) -> Result<SupportedMessage, StatusCode> {
        let browse_results = if request.nodes_to_browse.is_some() {
            let nodes_to_browse = request.nodes_to_browse.as_ref().unwrap();

            if !request.view.view_id.is_null() {
                // Views are not supported
                info!("Browse request ignored because view was specified (views not supported)");
                return Ok(self.service_fault(&request.request_header, StatusCode::BadViewIdUnknown));
            }

            Some(Self::browse_nodes(session, address_space, nodes_to_browse, request.requested_max_references_per_node as usize))
        } else {
            // Nothing to do
            return Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo));
        };

        let diagnostic_infos = None;
        let response = BrowseResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results: browse_results,
            diagnostic_infos,
        };

        Ok(response.into())
    }

    pub fn browse_next(&self, session: &mut Session, address_space: &AddressSpace, request: &BrowseNextRequest) -> Result<SupportedMessage, StatusCode> {
        if request.continuation_points.is_none() {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        } else {
            let continuation_points = request.continuation_points.as_ref().unwrap();
            let results = if request.release_continuation_points {
                session.remove_browse_continuation_points(continuation_points);
                None
            } else {
                // Iterate from the continuation point, assuming it is valid
                let results = continuation_points.iter().map(|continuation_point| {
                    Self::browse_from_continuation_point(session, address_space, continuation_point)
                }).collect();
                Some(results)
            };

            let diagnostic_infos = None;
            let response = BrowseNextResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results,
                diagnostic_infos,
            };
            Ok(response.into())
        }
    }

    pub fn translate_browse_paths_to_node_ids(&self, address_space: &AddressSpace, request: &TranslateBrowsePathsToNodeIdsRequest) -> Result<SupportedMessage, StatusCode> {
        trace!("TranslateBrowsePathsToNodeIdsRequest = {:?}", &request);
        // TODO this should be a server constant
        let max_nodes_per_operation = 0;

        if let Some(ref browse_paths) = request.browse_paths {
            if browse_paths.is_empty() {
                trace!("Browse paths is empty");
                Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
            } else if max_nodes_per_operation > 0 && browse_paths.len() > max_nodes_per_operation {
                trace!("Browse paths size {} exceeds max nodes {}", browse_paths.len(), max_nodes_per_operation);
                Ok(self.service_fault(&request.request_header, StatusCode::BadTooManyOperations))
            } else {
                let results = browse_paths.iter().enumerate().map(|(i, browse_path)| {
                    trace!("Processing browse path {}", i);
                    let node_id = browse_path.starting_node.clone();
                    if browse_path.relative_path.elements.is_none() {
                        BrowsePathResult {
                            status_code: StatusCode::BadNothingToDo,
                            targets: None,
                        }
                    } else {
                        // Starting from the node_id, find paths
                        match relative_path::find_nodes_relative_path(address_space, &node_id, &browse_path.relative_path) {
                            Err(err) => {
                                trace!("Browse path result for find nodes returned in error {}", err.name());
                                BrowsePathResult {
                                    status_code: err,
                                    targets: None,

                                }
                            }
                            Ok(result) => {
                                let targets = if !result.is_empty() {
                                    use std::u32;
                                    let targets = result.iter().map(|node_id| {
                                        BrowsePathTarget {
                                            target_id: ExpandedNodeId::new(node_id.clone()),
                                            remaining_path_index: u32::MAX,
                                        }
                                    }).collect();
                                    Some(targets)
                                } else {
                                    None
                                };
                                BrowsePathResult {
                                    status_code: StatusCode::Good,
                                    targets,
                                }
                            }
                        }
                    }
                }).collect();

                let response = TranslateBrowsePathsToNodeIdsResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos: None,
                };

                Ok(response.into())
            }
        } else {
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }

    fn browse_nodes(session: &mut Session, address_space: &AddressSpace, nodes_to_browse: &[BrowseDescription], max_references_per_node: usize) -> Vec<BrowseResult> {
        nodes_to_browse.iter().map(|node_to_browse| {
            match Self::browse_node(session, &address_space, 0, node_to_browse, max_references_per_node) {
                Ok(browse_result) => browse_result,
                Err(status_code) => BrowseResult {
                    status_code,
                    continuation_point: ByteString::null(),
                    references: None,
                }
            }
        }).collect()
    }

    fn browse_node(session: &mut Session, address_space: &AddressSpace, starting_index: usize, node_to_browse: &BrowseDescription, max_references_per_node: usize) -> Result<BrowseResult, StatusCode> {
        // Node must exist or there will be no references
        if node_to_browse.node_id.is_null() || !address_space.node_exists(&node_to_browse.node_id) {
            return Err(StatusCode::BadNodeIdUnknown);
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

        let result_mask = BrowseDescriptionResultMask::from_bits_truncate(node_to_browse.result_mask);
        let node_class_mask = node_to_browse.node_class_mask;

        // Construct descriptions for each reference
        let mut reference_descriptions: Vec<ReferenceDescription> = Vec::with_capacity(max_references_per_node);
        for (idx, reference) in references.iter().enumerate() {
            if idx < starting_index {
                continue;
            }
            let target_node_id = reference.target_node_id.clone();
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
            if node_class_mask != 0 && node_class_mask & (target_node_class as u32) == 0 {
                continue;
            }

            // Prepare the values to put into the struct according to the result mask
            let reference_type_id = if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_REFERENCE_TYPE) {
                reference.reference_type_id.clone()
            } else {
                NodeId::null()
            };
            let is_forward = if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_IS_FORWARD) {
                idx < inverse_ref_idx
            } else {
                true
            };

            let target_node_class = if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_NODE_CLASS) {
                target_node_class
            } else {
                NodeClass::Unspecified
            };
            let browse_name = if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_BROWSE_NAME) {
                target_node.browse_name().clone()
            } else {
                QualifiedName::null()
            };
            let display_name = if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_DISPLAY_NAME) {
                target_node.display_name().clone()
            } else {
                LocalizedText::null()
            };
            let type_definition = if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION) {
                // Type definition NodeId of the TargetNode. Type definitions are only available
                // for the NodeClasses Object and Variable. For all other NodeClasses a null NodeId
                // shall be returned.
                match target_node_class {
                    NodeClass::Object | NodeClass::Variable => {
                        let type_defs = address_space.find_references_from(&target_node.node_id(), Some((ReferenceTypeId::HasTypeDefinition, false)));
                        if let Some(type_defs) = type_defs {
                            ExpandedNodeId::new(type_defs[0].target_node_id.clone())
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
                node_id: ExpandedNodeId::new(target_node_id),
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
        } else {
            // Not valid or missing
            BrowseResult {
                status_code: StatusCode::BadContinuationPointInvalid,
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
            //  already has a ref counted reference_descriptions. We could clone the Arc if the fn could
            //  be factored to allow for that

            // Create a continuation point for the remainder of the result. The point will hold the entire result
            let continuation_point = ByteString::random(6);
            session.add_browse_continuation_point(BrowseContinuationPoint {
                id: continuation_point.clone(),
                address_space_last_modified: address_space.last_modified(),
                max_references_per_node,
                starting_index: ending_index,
                reference_descriptions: Arc::new(Mutex::new(reference_descriptions.to_vec())),
            });
            (reference_descriptions_slice, continuation_point)
        } else {
            let reference_descriptions_slice = reference_descriptions[starting_index..].to_vec();
            (reference_descriptions_slice, ByteString::null())
        };
        BrowseResult {
            status_code: StatusCode::Good,
            continuation_point,
            references: Some(reference_descriptions),
        }
    }
}