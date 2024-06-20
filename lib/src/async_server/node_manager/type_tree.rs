use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
};

use crate::server::prelude::{
    DataTypeId, NodeClass, NodeId, ObjectTypeId, QualifiedName, ReferenceTypeId, VariableTypeId,
};

#[derive(PartialEq, Eq, Hash)]
struct TypePropertyKey {
    path: Vec<QualifiedName>,
}
// NOTE: This implementation means that TypePropertyKey must have the same
// hash as an equivalent &[QualifiedName]
impl Borrow<[QualifiedName]> for TypePropertyKey {
    fn borrow(&self) -> &[QualifiedName] {
        &self.path
    }
}

pub struct TypeProperty {
    pub node_id: NodeId,
    pub node_class: NodeClass,
}

/// Type managing the types in an OPC-UA server.
/// The server needs to know about all available types, to handle things like
/// event filters, browse filtering, etc.
///
/// Each node manager is responsible for populating the type tree with
/// its types.
pub struct TypeTree {
    nodes: HashMap<NodeId, NodeClass>,
    subtypes_by_source: HashMap<NodeId, HashSet<NodeId>>,
    subtypes_by_target: HashMap<NodeId, NodeId>,
    type_properties: HashMap<NodeId, HashMap<TypePropertyKey, TypeProperty>>,
}

impl TypeTree {
    pub fn is_subtype_of(&self, child: &NodeId, ancestor: &NodeId) -> bool {
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

    pub fn get(&self, node: &NodeId) -> Option<NodeClass> {
        self.nodes.get(node).cloned()
    }

    pub fn new() -> Self {
        let mut type_tree = Self {
            nodes: HashMap::new(),
            subtypes_by_source: HashMap::new(),
            subtypes_by_target: HashMap::new(),
            type_properties: HashMap::new(),
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

    pub fn add_type_node(&mut self, id: &NodeId, parent: &NodeId, node_class: NodeClass) {
        self.nodes.insert(id.clone(), node_class);
        self.subtypes_by_source
            .entry(parent.clone())
            .or_default()
            .insert(id.clone());
        self.subtypes_by_target.insert(id.clone(), parent.clone());
    }

    pub fn add_type_property(
        &mut self,
        id: &NodeId,
        typ: &NodeId,
        path: &[&QualifiedName],
        node_class: NodeClass,
    ) {
        let props = match self.type_properties.get_mut(typ) {
            Some(x) => x,
            None => self.type_properties.entry(typ.clone()).or_default(),
        };

        props.insert(
            TypePropertyKey {
                path: path.iter().map(|n| (*n).to_owned()).collect(),
            },
            TypeProperty {
                node_class,
                node_id: id.clone(),
            },
        );
    }

    pub fn find_type_prop_by_browse_path(
        &self,
        type_id: &NodeId,
        path: &[QualifiedName],
    ) -> Option<&TypeProperty> {
        self.type_properties.get(type_id).and_then(|p| p.get(path))
    }
}
