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

#[derive(Clone, Debug)]
pub struct TypeProperty {
    pub node_id: NodeId,
    pub node_class: NodeClass,
}

#[derive(Clone, Debug)]
pub struct TypePropertyInverseRef {
    pub type_id: NodeId,
    pub path: Vec<QualifiedName>,
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
    property_to_type: HashMap<NodeId, TypePropertyInverseRef>,
    type_properties: HashMap<NodeId, HashMap<TypePropertyKey, TypeProperty>>,
}

#[derive(Clone, Debug)]
pub enum TypeTreeNode<'a> {
    Type(NodeClass),
    Property(&'a TypePropertyInverseRef),
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

    pub fn get_node<'a>(&'a self, node: &NodeId) -> Option<TypeTreeNode<'a>> {
        if let Some(n) = self.nodes.get(node) {
            return Some(TypeTreeNode::Type(*n));
        }
        if let Some(p) = self.property_to_type.get(node) {
            return Some(TypeTreeNode::Property(p));
        }
        None
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
            property_to_type: HashMap::new(),
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

        let path_owned: Vec<_> = path.iter().map(|n| (*n).to_owned()).collect();

        props.insert(
            TypePropertyKey {
                path: path_owned.clone(),
            },
            TypeProperty {
                node_class,
                node_id: id.clone(),
            },
        );

        self.property_to_type.insert(
            id.clone(),
            TypePropertyInverseRef {
                type_id: typ.clone(),
                path: path_owned,
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

    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        if self.nodes.remove(node_id).is_some() {
            let props = self.type_properties.remove(node_id);
            if let Some(props) = props {
                for prop in props.values() {
                    self.property_to_type.remove(&prop.node_id);
                }
            }
            if let Some(parent) = self.subtypes_by_target.remove(node_id) {
                if let Some(types) = self.subtypes_by_source.get_mut(&parent) {
                    types.remove(node_id);
                }
            }
            return true;
        }
        if let Some(prop) = self.property_to_type.remove(node_id) {
            let props = self.type_properties.get_mut(&prop.type_id);
            if let Some(props) = props {
                props.remove(&prop.path as &[QualifiedName]);
            }
            return true;
        }
        false
    }
}
