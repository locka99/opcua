use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
};

use crate::types::{
    DataTypeId, NodeClass, NodeId, ObjectTypeId, QualifiedName, ReferenceTypeId, VariableTypeId,
};

use super::build::NamespaceMap;

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
/// A single property of a type in the type tree.
pub struct TypeProperty {
    /// Node ID of the property.
    pub node_id: NodeId,
    /// Node class of the property.
    pub node_class: NodeClass,
}

#[derive(Clone, Debug)]
/// Inverse reference to a type from a property.
pub struct TypePropertyInverseRef {
    /// Node ID of the type.
    pub type_id: NodeId,
    /// Path to the property.
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
    namespaces: NamespaceMap,
}

#[derive(Clone, Debug)]
/// A node in the type tree.
pub enum TypeTreeNode<'a> {
    /// A registered type.
    Type(NodeClass),
    /// A property of a type.
    Property(&'a TypePropertyInverseRef),
}

impl TypeTree {
    /// Return `true` if `child` is a subtype of `ancestor`, or if `child` and
    /// `ancestor` is the same node, i.e. subtype in the OPC-UA sense.
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

    /// Get a reference to a node in the type tree.
    pub fn get_node<'a>(&'a self, node: &NodeId) -> Option<TypeTreeNode<'a>> {
        if let Some(n) = self.nodes.get(node) {
            return Some(TypeTreeNode::Type(*n));
        }
        if let Some(p) = self.property_to_type.get(node) {
            return Some(TypeTreeNode::Property(p));
        }
        None
    }

    /// Get a type from the type tree.
    pub fn get(&self, node: &NodeId) -> Option<NodeClass> {
        self.nodes.get(node).cloned()
    }

    /// Create a new type tree with just the root nodes added.
    pub fn new() -> Self {
        let mut type_tree = Self {
            nodes: HashMap::new(),
            subtypes_by_source: HashMap::new(),
            subtypes_by_target: HashMap::new(),
            type_properties: HashMap::new(),
            property_to_type: HashMap::new(),
            namespaces: NamespaceMap::new(),
        };
        type_tree
            .namespaces
            .add_namespace("http://opcfoundation.org/UA/");
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

    /// Add a new type to the type tree.
    pub fn add_type_node(&mut self, id: &NodeId, parent: &NodeId, node_class: NodeClass) {
        self.nodes.insert(id.clone(), node_class);
        self.subtypes_by_source
            .entry(parent.clone())
            .or_default()
            .insert(id.clone());
        self.subtypes_by_target.insert(id.clone(), parent.clone());
    }

    /// Add a new property to the type tree.
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

    /// Find a property by browse and type ID.
    pub fn find_type_prop_by_browse_path(
        &self,
        type_id: &NodeId,
        path: &[QualifiedName],
    ) -> Option<&TypeProperty> {
        self.type_properties.get(type_id).and_then(|p| p.get(path))
    }

    /// Remove a node from the type tree.
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

    pub fn namespaces(&self) -> &NamespaceMap {
        &self.namespaces
    }

    pub fn namespaces_mut(&mut self) -> &mut NamespaceMap {
        &mut self.namespaces
    }
}
