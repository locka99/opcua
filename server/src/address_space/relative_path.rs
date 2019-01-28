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
    match address_space.find_node(node_id) {
        None => {
            trace!("find_nodes_relative_path cannot find node {:?}", node_id);
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
                        // Iterate current set of nodes and put the results into next
                        if let Some(mut result) = follow_relative_path(address_space, &node_id, element) {
                            next_matching_nodes.append(&mut result);
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
