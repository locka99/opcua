// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::collections::HashSet;

use crate::types::{
    node_id::NodeId,
    service_types::{RelativePath, RelativePathElement},
    status_code::StatusCode,
    QualifiedName,
};

use super::{node::NodeType, AddressSpace};

/// Given a browse path consisting of browse names, walk nodes from the root until we find a single node (or not).
/// This function is a simplified use case for event filters and such like where a browse path
/// is defined as an array and doesn't need to be parsed out of a relative path. All nodes in the
/// path must be objects or variables.
pub(crate) fn find_node_from_browse_path<'a>(
    address_space: &'a AddressSpace,
    parent_node_id: &NodeId,
    browse_path: &[QualifiedName],
) -> Result<&'a NodeType, StatusCode> {
    if browse_path.is_empty() {
        Err(StatusCode::BadNotFound)
    } else {
        // Each instance declaration in the path shall be an object or variable node. The final node in the
        // path may be an object node; however, object nodes are only available for Events which are
        // visible in the server's address space
        let mut parent_node_id = parent_node_id.clone();
        for browse_name in browse_path {
            if let Some(child_nodes) = address_space.find_hierarchical_references(&parent_node_id) {
                let found_node_id = child_nodes.iter().find(|node_id| {
                    if let Some(node) = address_space.find_node(node_id) {
                        if node.as_node().browse_name() == *browse_name {
                            // Check that the node is an Object or Variable
                            matches!(node, NodeType::Object(_) | NodeType::Variable(_))
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });
                if let Some(found_node_id) = found_node_id {
                    parent_node_id = found_node_id.clone();
                } else {
                    //debug!(
                    //    "Cannot find node under {} with browse_path of {:?}/1",
                    //    parent_node_id, browse_path
                    //);
                    return Err(StatusCode::BadNotFound);
                }
            } else {
                //debug!(
                //    "Cannot find node under {} with browse_path of {:?}/2",
                //    parent_node_id, browse_path
                //);
                return Err(StatusCode::BadNotFound);
            }
        }
        Ok(address_space.find_node(&parent_node_id).unwrap())
    }
}

/// Given a path as a string, find all the nodes that match against it. Note this function
/// uses a default path resolver based on common browse names. If you need something else use
/// `find_nodes_relative_path()` after you have created a relative path.
pub fn find_nodes_relative_path_simple(
    address_space: &AddressSpace,
    node_id: &NodeId,
    relative_path: &str,
) -> Result<Vec<NodeId>, StatusCode> {
    let relative_path =
        RelativePath::from_str(relative_path, &RelativePathElement::default_node_resolver)
            .map_err(|_| StatusCode::BadUnexpectedError)?;
    find_nodes_relative_path(address_space, node_id, &relative_path)
}

/// Given a `RelativePath`, find all the nodes that match against it.
pub fn find_nodes_relative_path(
    address_space: &AddressSpace,
    node_id: &NodeId,
    relative_path: &RelativePath,
) -> Result<Vec<NodeId>, StatusCode> {
    match address_space.find_node(node_id) {
        None => {
            trace!("find_nodes_relative_path cannot find node {}", node_id);
            Err(StatusCode::BadNodeIdUnknown)
        }
        Some(_) => {
            let elements = relative_path.elements.as_ref().unwrap();
            if elements.is_empty() {
                warn!("find_nodes_relative_path elements are empty");
                Err(StatusCode::BadNothingToDo)
            } else {
                let mut matching_nodes = vec![node_id.clone()];
                let mut next_matching_nodes = Vec::with_capacity(100);

                // Traverse the relative path elements. Each time around, we will find the matching
                // elements at that level using the next element
                for element in elements.iter() {
                    if element.target_name.is_null() {
                        warn!("find_nodes_relative_path browse name is invalid (null)");
                        return Err(StatusCode::BadBrowseNameInvalid);
                    }

                    next_matching_nodes.clear();

                    matching_nodes.drain(..).for_each(|node_id| {
                        trace!("Following relative path on node {}", node_id);
                        // Iterate current set of nodes and put the results into next
                        if let Some(mut result) =
                            follow_relative_path(address_space, &node_id, element)
                        {
                            trace!("  Found matching nodes {:#?}", result);
                            next_matching_nodes.append(&mut result);
                        } else {
                            trace!("  Found no matching nodes");
                        }
                    });
                    if next_matching_nodes.is_empty() {
                        break;
                    } else {
                        matching_nodes.append(&mut next_matching_nodes);
                    }
                }

                if matching_nodes.is_empty() {
                    warn!("find_nodes_relative_path bad no match");
                    Err(StatusCode::BadNoMatch)
                } else {
                    Ok(matching_nodes)
                }
            }
        }
    }
}

fn follow_relative_path(
    address_space: &AddressSpace,
    node_id: &NodeId,
    relative_path: &RelativePathElement,
) -> Option<Vec<NodeId>> {
    let reference_filter = {
        if let Ok(reference_type_id) = relative_path.reference_type_id.as_reference_type_id() {
            Some((reference_type_id, relative_path.include_subtypes))
        } else {
            None
        }
    };
    let references = if relative_path.is_inverse {
        address_space.find_inverse_references(node_id, reference_filter)
    } else {
        address_space.find_references(node_id, reference_filter)
    };
    if let Some(references) = references {
        let compare_target_name = !relative_path.target_name.is_null();
        let mut result = Vec::with_capacity(references.len());
        for reference in &references {
            if let Some(node) = address_space.find_node(&reference.target_node) {
                let node = node.as_node();
                if !compare_target_name || node.browse_name() == relative_path.target_name {
                    result.push(reference.target_node.clone());
                }
            }
        }
        // Vector may contain duplicates, so reduce those to a unique set
        let result = result.into_iter().collect::<HashSet<NodeId>>();
        // Now the result as a vec
        Some(result.into_iter().collect())
    } else {
        None
    }
}
