// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

use std::result::Result;
use std::sync::{Arc, Mutex, RwLock};

use opcua_core::supported_message::SupportedMessage;
use opcua_crypto::random;
use opcua_types::{
    *,
    node_ids::ReferenceTypeId,
    status_code::StatusCode,
};

use crate::{
    address_space::{AddressSpace, relative_path},
    continuation_point::BrowseContinuationPoint,
    services::Service,
    session::Session,
    state::ServerState,
};

/// The view service. Allows the client to browse the address space of the server.
pub(crate) struct ViewService;

impl Service for ViewService {
    fn name(&self) -> String { String::from("ViewService") }
}

impl ViewService {
    pub fn new() -> ViewService {
        ViewService {}
    }

    pub fn browse(&self, session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>, request: &BrowseRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_browse) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut session = trace_write_lock_unwrap!(session);
            let address_space = trace_read_lock_unwrap!(address_space);

            let view = &request.view;
            if !view.view_id.is_null() || !view.timestamp.is_null() {
                // Views are not supported
                info!("Browse request ignored because view was specified (views not supported)");
                self.service_fault(&request.request_header, StatusCode::BadViewIdUnknown)
            } else {
                // debug!("Browse request = {:#?}", request);
                let nodes_to_browse = request.nodes_to_browse.as_ref().unwrap();

                // Max references per node. This should be server configurable but the constant
                // is generous.
                const DEFAULT_MAX_REFERENCES_PER_NODE: u32 = 256;
                let max_references_per_node = if request.requested_max_references_per_node == 0 {
                    // Client imposes no limit
                    DEFAULT_MAX_REFERENCES_PER_NODE
                } else if request.requested_max_references_per_node > DEFAULT_MAX_REFERENCES_PER_NODE {
                    // Client limit exceeds default
                    DEFAULT_MAX_REFERENCES_PER_NODE
                } else {
                    request.requested_max_references_per_node
                };

                // Browse the nodes
                let results = Some(Self::browse_nodes(&mut session, &address_space, nodes_to_browse, max_references_per_node as usize));
                let diagnostic_infos = None;
                BrowseResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results,
                    diagnostic_infos,
                }.into()
            }
        }
    }

    pub fn browse_next(&self, session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>, request: &BrowseNextRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.continuation_points) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut session = trace_write_lock_unwrap!(session);
            let address_space = trace_read_lock_unwrap!(address_space);

            let continuation_points = request.continuation_points.as_ref().unwrap();
            let results = if request.release_continuation_points {
                session.remove_browse_continuation_points(continuation_points);
                None
            } else {
                // Iterate from the continuation point, assuming it is valid
                session.remove_expired_browse_continuation_points(&address_space);
                let results = continuation_points.iter().map(|continuation_point| {
                    Self::browse_from_continuation_point(&mut session, &address_space, continuation_point)
                }).collect();
                Some(results)
            };

            let diagnostic_infos = None;
            BrowseNextResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results,
                diagnostic_infos,
            }.into()
        }
    }

    pub fn translate_browse_paths_to_node_ids(&self, server_state: Arc<RwLock<ServerState>>, address_space: Arc<RwLock<AddressSpace>>, request: &TranslateBrowsePathsToNodeIdsRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.browse_paths) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let server_state = trace_read_lock_unwrap!(server_state);
            let address_space = trace_read_lock_unwrap!(address_space);

            let browse_paths = request.browse_paths.as_ref().unwrap();
            let max_browse_paths_per_translate = server_state.max_browse_paths_per_translate();
            if browse_paths.len() > max_browse_paths_per_translate {
                trace!("Browse paths size {} exceeds max nodes {}", browse_paths.len(), max_browse_paths_per_translate);
                self.service_fault(&request.request_header, StatusCode::BadTooManyOperations)
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
                        match relative_path::find_nodes_relative_path(&address_space, &node_id, &browse_path.relative_path) {
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

                TranslateBrowsePathsToNodeIdsResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos: None,
                }.into()
            }
        }
    }

    pub fn register_nodes(&self, server_state: Arc<RwLock<ServerState>>, session: Arc<RwLock<Session>>, request: &RegisterNodesRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_register) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut server_state = trace_write_lock_unwrap!(server_state);
            if let Some(ref mut callback) = server_state.register_nodes_callback {
                let nodes_to_register = request.nodes_to_register.as_ref().unwrap();
                match callback.register_nodes(session, &nodes_to_register[..]) {
                    Ok(registered_node_ids) => {
                        RegisterNodesResponse {
                            response_header: ResponseHeader::new_good(&request.request_header),
                            registered_node_ids: Some(registered_node_ids),
                        }.into()
                    }
                    Err(err) => {
                        self.service_fault(&request.request_header, err)
                    }
                }
            } else {
                self.service_fault(&request.request_header, StatusCode::BadNodeIdInvalid)
            }
        }
    }

    pub fn unregister_nodes(&self, server_state: Arc<RwLock<ServerState>>, session: Arc<RwLock<Session>>, request: &UnregisterNodesRequest) -> SupportedMessage {
        if is_empty_option_vec!(request.nodes_to_unregister) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut server_state = trace_write_lock_unwrap!(server_state);
            if let Some(ref mut callback) = server_state.unregister_nodes_callback {
                let nodes_to_unregister = request.nodes_to_unregister.as_ref().unwrap();
                match callback.unregister_nodes(session, &nodes_to_unregister[..]) {
                    Ok(_) => {
                        UnregisterNodesResponse {
                            response_header: ResponseHeader::new_good(&request.request_header),
                        }.into()
                    }
                    Err(err) => {
                        self.service_fault(&request.request_header, err)
                    }
                }
            } else {
                UnregisterNodesResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                }.into()
            }
        }
    }

    fn browse_nodes(session: &mut Session, address_space: &AddressSpace, nodes_to_browse: &[BrowseDescription], max_references_per_node: usize) -> Vec<BrowseResult> {
        nodes_to_browse.iter().map(|node_to_browse| {
            match Self::browse_node(session, address_space, 0, node_to_browse, max_references_per_node) {
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
        let node_class_mask = NodeClassMask::from_bits_truncate(node_to_browse.node_class_mask);

        // Construct descriptions for each reference
        let mut reference_descriptions: Vec<ReferenceDescription> = Vec::with_capacity(max_references_per_node);
        for (idx, reference) in references.iter().enumerate() {
            if idx < starting_index {
                continue;
            }
            let target_node_id = reference.target_node.clone();
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
            if target_node_class != NodeClass::Unspecified && !node_class_mask.is_empty() {
                let target_node_class = NodeClassMask::from_bits_truncate(target_node_class as u32);
                if !node_class_mask.contains(target_node_class) {
                    continue;
                }
            }

            // Prepare the values to put into the struct according to the result mask
            let reference_type_id = if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_REFERENCE_TYPE) {
                reference.reference_type.clone()
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
                        let type_defs = address_space.find_references(&target_node.node_id(), Some((ReferenceTypeId::HasTypeDefinition, false)));
                        if let Some(type_defs) = type_defs {
                            ExpandedNodeId::new(type_defs[0].target_node.clone())
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
        if let Some(continuation_point) = session.find_browse_continuation_point(continuation_point) {
            let reference_descriptions = continuation_point.reference_descriptions.lock().unwrap();
            // Use the existing result. This may result in another continuation point being created
            Self::reference_description_to_browse_result(session, address_space, &reference_descriptions, continuation_point.starting_index, continuation_point.max_references_per_node)
        } else {
            // Not valid or missing
            error!("Continuation point {} was invalid", continuation_point.as_base64());
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
            let continuation_point = random::byte_string(6);
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