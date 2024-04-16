use std::collections::HashMap;

use crate::server::prelude::{NodeId, NodeType};

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Reference<'a> {
    pub reference_type: &'a NodeId,
    pub target_node: &'a NodeId,
}

pub struct References {
    /// Map from source node, to node type, to target nodes
    references: HashMap<NodeId, HashMap<NodeId, Vec<NodeId>>>,
}

/// Represents an in-memory address space.
pub struct AddressSpace {
    node_map: HashMap<NodeId, NodeType>,
    namespaces: HashMap<usize, String>,
}
