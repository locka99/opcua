use std::collections::{HashMap, HashSet};

use crate::server::prelude::{
    DataTypeId, NodeClass, NodeId, ObjectTypeId, ReferenceTypeId, VariableTypeId,
};

/// Type managing the types in an OPC-UA server.
/// Types are usually known beforehand (though this is not guaranteed),
///
pub struct DefaultTypeTree {
    nodes: HashMap<NodeId, NodeClass>,
    subtypes_by_source: HashMap<NodeId, HashSet<NodeId>>,
    subtypes_by_target: HashMap<NodeId, NodeId>,
}

pub trait TypeTree {
    /// Return `true` if the node given by `child` is a hierarchical
    /// descendant of `ancestor`, or `child == ancestor`
    /// If either node does not exist, return `false`.
    fn is_child_of(&self, child: &NodeId, ancestor: &NodeId) -> bool;

    /// Return the node class of the given node, if it exists, otherwise return `None`
    fn get(&self, node: &NodeId) -> Option<NodeClass>;
}

impl TypeTree for DefaultTypeTree {
    fn is_child_of(&self, child: &NodeId, ancestor: &NodeId) -> bool {
        let mut node = child;
        loop {
            if node == ancestor {
                break true;
            }

            let Some(class) = self.nodes.get(node) else {
                break false;
            };

            if !matches!(
                class,
                NodeClass::DataType
                    | NodeClass::ObjectType
                    | NodeClass::ReferenceType
                    | NodeClass::VariableType
            ) {
                break false;
            }

            match self.subtypes_by_target.get(node) {
                Some(n) => node = n,
                None => break false,
            }
        }
    }

    fn get(&self, node: &NodeId) -> Option<NodeClass> {
        self.nodes.get(node).cloned()
    }
}

impl DefaultTypeTree {
    pub fn new() -> Self {
        let mut type_tree = Self {
            nodes: HashMap::new(),
            subtypes_by_source: HashMap::new(),
            subtypes_by_target: HashMap::new(),
        };
        type_tree
            .nodes
            .insert(ObjectTypeId::BaseObjectType.into(), NodeClass::ObjectType);
        type_tree
            .nodes
            .insert(ReferenceTypeId::References.into(), NodeClass::ReferenceType);
        type_tree.nodes.insert(
            VariableTypeId::BaseVariableType.into(),
            NodeClass::VariableType,
        );
        type_tree
            .nodes
            .insert(DataTypeId::BaseDataType.into(), NodeClass::DataType);
        type_tree
    }

    pub fn add_node(&mut self, id: &NodeId, parent: &NodeId, node_class: NodeClass) {
        self.nodes.insert(id.clone(), node_class);
        self.subtypes_by_source
            .entry(parent.clone())
            .or_default()
            .insert(id.clone());
        self.subtypes_by_target.insert(id.clone(), parent.clone());
    }
}
