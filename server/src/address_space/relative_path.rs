use opcua_types::{
    status_code::StatusCode,
    node_id::NodeId,
    service_types::{RelativePath, RelativePathElement},
};

use crate::{
    address_space::AddressSpace
};

/// Given a `RelativePath`, find all the nodes that match against it.
pub(crate) fn find_nodes_relative_path(address_space: &AddressSpace, node_id: &NodeId, relative_path: &RelativePath) -> Result<Vec<NodeId>, StatusCode> {
    // TODO THIS CODE IS PROBABLY BROKEN - need test examples for TranslateBrowsePathToNodeIds
    if address_space.find_node(node_id).is_none() {
        Err(StatusCode::BadNodeIdUnknown)
    } else {
        let elements = relative_path.elements.as_ref().unwrap();
        if elements.is_empty() {
            Err(StatusCode::BadNothingToDo)
        } else {
            let mut matching_nodes = vec![node_id.clone()];
            let mut next_matching_nodes = Vec::with_capacity(100);

            // Traverse the relative path elements
            for relative_path_element in elements.iter() {
                next_matching_nodes.clear();

                if matching_nodes.is_empty() {
                    break;
                }

                for node_id in &matching_nodes {
                    // Iterate current set of nodes and put the results into next
                    if let Some(mut result) = follow_relative_path(address_space, &node_id, relative_path_element) {
                        next_matching_nodes.append(&mut result);
                    }
                }

                matching_nodes.clear();
                matching_nodes.append(&mut next_matching_nodes);
            }

            Ok(matching_nodes)
        }
    }
}

fn follow_relative_path(address_space: &AddressSpace, node_id: &NodeId, relative_path: &RelativePathElement) -> Option<Vec<NodeId>> {
    let reference_type_id = relative_path.reference_type_id.as_reference_type_id().unwrap();
    let reference_filter = Some((reference_type_id, relative_path.include_subtypes));
    let references = if relative_path.is_inverse {
        address_space.find_references_to(node_id, reference_filter)
    } else {
        address_space.find_references_from(node_id, reference_filter)
    };
    if let Some(references) = references {
        let compare_target_name = !relative_path.target_name.is_null();
        let mut result = Vec::with_capacity(references.len());
        for reference in &references {
            if let Some(node) = address_space.find_node(&reference.node_id) {
                let node = node.as_node();
                if !compare_target_name || node.browse_name() == relative_path.target_name {
                    result.push(reference.node_id.clone());
                }
            }
        }
        Some(result)
    } else {
        None
    }
}