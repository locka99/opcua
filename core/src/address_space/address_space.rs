use std::collections::HashMap;

use address_space::*;
use types::*;


pub enum NodeType {
    Object(Object),
    ObjectType(ObjectType),
    ReferenceType(ReferenceType),
    Variable(Variable),
    VariableType(VariableType),
    View(View),
    DataType(DataType),
    Method(Method),
}

impl NodeType {
    pub fn as_node(&self) -> &Node {
        match self {
            &NodeType::Object(ref value) => value,
            &NodeType::ObjectType(ref value) => value,
            &NodeType::ReferenceType(ref value) => value,
            &NodeType::Variable(ref value) => value,
            &NodeType::VariableType(ref value) => value,
            &NodeType::View(ref value) => value,
            &NodeType::DataType(ref value) => value,
            &NodeType::Method(ref value) => value,
        }
    }
}


pub struct AddressSpace {
    pub node_map: HashMap<NodeId, NodeType>,
}

impl AddressSpace {
    pub fn new_top_level() -> AddressSpace {
        // Construct the Root folder and the top level nodes

        let root_node_id = AddressSpace::root_folder_id();
        let mut root_node = Object::new(&root_node_id, "Root", "Root");

        let objects_node_id = AddressSpace::objects_folder_id();
        let objects_node = Object::new(&objects_node_id, "Objects", "Objects");
        // Organizes - Top level server

        let types_node_id = AddressSpace::types_folder_id();
        let types_node = Object::new(&types_node_id, "Types", "Types");

        let views_node_id = AddressSpace::views_folder_id();
        let views_node = Object::new(&views_node_id, "Views", "Views");

        root_node.add_organizes(&objects_node_id);
        root_node.add_organizes(&types_node_id);
        root_node.add_organizes(&views_node_id);

        let mut address_space = AddressSpace {
            node_map: HashMap::new(),
        };

        address_space.insert(root_node_id, NodeType::Object(root_node));
        address_space.insert(objects_node_id, NodeType::Object(objects_node));
        address_space.insert(types_node_id, NodeType::Object(types_node));
        address_space.insert(views_node_id, NodeType::Object(views_node));

        // TODO
        // add Server (ServerType)

        address_space
    }

    pub fn root_folder_id() -> NodeId {
        ObjectId::ObjectsFolder.as_node_id()
    }

    pub fn objects_folder_id() -> NodeId {
        ObjectId::ObjectsFolder.as_node_id()
    }

    pub fn types_folder_id() -> NodeId {
        ObjectId::TypesFolder.as_node_id()
    }

    pub fn views_folder_id() -> NodeId {
        ObjectId::ViewsFolder.as_node_id()
    }

    pub fn root_folder(&self) -> &Object {
        if let &NodeType::Object(ref node) = self.find(&AddressSpace::root_folder_id()).unwrap() {
            node
        } else {
            panic!("There should be a root node!");
        }
    }

    pub fn objects_folder(&self) -> &Object {
        if let &NodeType::Object(ref node) = self.find(&AddressSpace::objects_folder_id()).unwrap() {
            node
        } else {
            panic!("There should be an objects node!");
        }
    }

    pub fn types_folder(&self) -> &Object {
        if let &NodeType::Object(ref node) = self.find(&AddressSpace::types_folder_id()).unwrap() {
            node
        } else {
            panic!("There should be a types node!");
        }
    }

    pub fn views_folder(&self) -> &Object {
        if let &NodeType::Object(ref node) = self.find(&AddressSpace::views_folder_id()).unwrap() {
            node
        } else {
            panic!("There should be a views node!");
        }
    }

    pub fn insert(&mut self, node_id: NodeId, node_type: NodeType) {
        self.node_map.insert(node_id, node_type);
    }

    pub fn find(&self, node_id: &NodeId) -> Option<&NodeType> {
        if self.node_map.contains_key(node_id) {
            self.node_map.get(node_id)
        } else {
            None
        }
    }

    pub fn find_references_from(&self, node_id: &NodeId, reference_type_id: &Option<NodeId>) -> Option<Vec<Reference>> {
        let source_node = self.find(node_id);
        if source_node.is_none() {
            None
        } else {
            let source_node = source_node.unwrap();
            let result = if reference_type_id.is_none() {
                // Add everything
                source_node.as_node().references().clone()
            } else {
                // Filter by type
                let reference_type_id = reference_type_id.as_ref().unwrap().clone();
                let mut result = Vec::new();
                for reference in source_node.as_node().references() {
                    // TODO this should match on subtypes too
                    if NodeId::from_reference_type_id(reference.reference_type_id()) == reference_type_id {
                        result.push(reference.clone());
                    }
                }
                result
            };
            Some(result)
        }
    }

    pub fn find_references_to(&self, _: &NodeId, _: &Option<NodeId>) -> Option<Vec<Reference>> {
        // TODO inverse relationship
        None
    }
}
