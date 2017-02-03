use std::collections::HashMap;

use address_space::*;
use services::*;
use types::*;

#[derive(Debug, Clone, PartialEq)]
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
    pub references: HashMap<NodeId, Vec<Reference>>,
    pub inverse_references: HashMap<NodeId, Vec<Reference>>,
}

impl AddressSpace {
    pub fn new_top_level() -> AddressSpace {
        // Construct the Root folder and the top level nodes
        let mut address_space = AddressSpace {
            node_map: HashMap::new(),
            references: HashMap::new(),
            inverse_references: HashMap::new(),
        };

        // TODO use add_folder_type() function
        let root_node_id = AddressSpace::root_folder_id();
        let root_node = Object::new(&root_node_id, "Root", "Root");
        address_space.insert(&root_node_id, NodeType::Object(root_node));

        let objects_node_id = AddressSpace::objects_folder_id();
        address_space.add_folder_node_id(&objects_node_id, "Objects", "Objects", &root_node_id);

        let types_node_id = AddressSpace::types_folder_id();
        address_space.add_folder_node_id(&types_node_id, "Types", "Types", &root_node_id);
        // DataTypesFolder "DataTypes"
        //    OPC Binary

        // ReferenceTypesFolder "ReferenceTypes"
        //    References/

        // Server
        //   ServerType
        //   ServerStatus
        //   ServerCapabilities
        //   ServerArray
        //   NamespaceArray

        let views_node_id = AddressSpace::views_folder_id();
        address_space.add_folder_node_id(&views_node_id, "Views", "Views", &root_node_id);

        // TODO
        // add Server (ServerType)

        address_space
    }

    pub fn root_folder_id() -> NodeId {
        ObjectId::RootFolder.as_node_id()
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
        if let &NodeType::Object(ref node) = self.find_node(&AddressSpace::root_folder_id()).unwrap() {
            node
        } else {
            panic!("There should be a root node!");
        }
    }

    pub fn objects_folder(&self) -> &Object {
        if let &NodeType::Object(ref node) = self.find_node(&AddressSpace::objects_folder_id()).unwrap() {
            node
        } else {
            panic!("There should be an objects node!");
        }
    }

    pub fn types_folder(&self) -> &Object {
        if let &NodeType::Object(ref node) = self.find_node(&AddressSpace::types_folder_id()).unwrap() {
            node
        } else {
            panic!("There should be a types node!");
        }
    }

    pub fn views_folder(&self) -> &Object {
        if let &NodeType::Object(ref node) = self.find_node(&AddressSpace::views_folder_id()).unwrap() {
            node
        } else {
            panic!("There should be a views node!");
        }
    }

    pub fn insert(&mut self, node_id: &NodeId, node_type: NodeType) {
        self.node_map.insert(node_id.clone(), node_type);
    }

    pub fn node_exists(&self, node_id: &NodeId) -> bool {
        self.node_map.contains_key(node_id)
    }

    pub fn find_node(&self, node_id: &NodeId) -> Option<&NodeType> {
        if self.node_map.contains_key(node_id) {
            self.node_map.get(node_id)
        } else {
            None
        }
    }

    pub fn find_node_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeType> {
        if self.node_map.contains_key(node_id) {
            self.node_map.get_mut(node_id)
        } else {
            None
        }
    }

    pub fn add_folder_node_id(&mut self, node_id: &NodeId, browse_name: &str, display_name: &str, parent_node_id: &NodeId) -> bool {
        // Add a relationship to the parent
        self.add_organizes(&parent_node_id, &node_id);
        let folder_object = Object::new(&node_id, browse_name, display_name);
        self.make_twoway_reference(&folder_object.node_id(), &ObjectTypeId::FolderType.as_node_id(), ReferenceTypeId::HasTypeDefinition);
        self.insert(&node_id, NodeType::Object(folder_object));
        // TODO test for failure
        true
    }

    pub fn add_folder(&mut self, browse_name: &str, display_name: &str, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        let node_id = NodeId::next_numeric();
        if self.add_folder_node_id(&node_id, browse_name, display_name, parent_node_id) {
            Ok(node_id)
        } else {
            Err(())
        }
    }

    pub fn add_variables(&mut self, variables: &Vec<Variable>, parent_node_id: &NodeId) -> Vec<Result<NodeId, ()>> {
        let mut result = Vec::with_capacity(variables.len());
        for variable in variables {
            result.push(self.add_variable(variable, parent_node_id));
        }
        result
    }

    pub fn add_variable(&mut self, variable: &Variable, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        let node_id = variable.node_id();
        if !self.node_map.contains_key(&node_id) {
            self.add_organizes(&parent_node_id, &node_id);
            self.insert(&node_id, NodeType::Variable(variable.clone()));
            Ok(node_id)
        } else {
            Err(())
        }
    }

    fn add_reference(reference_map: &mut HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference: Reference) {
        if reference_map.contains_key(node_id) {
            let mut references = reference_map.get_mut(node_id).unwrap();
            references.push(reference);
        } else {
            reference_map.insert(node_id.clone(), vec![reference]);
        }
    }

    fn filter_references_by_type(references: &Vec<Reference>, reference_type_id: &Option<ReferenceTypeId>) -> Vec<Reference> {
        if reference_type_id.is_none() {
            references.clone()
        } else {
            // Filter by type
            let reference_type_id = reference_type_id.as_ref().unwrap();
            let mut result = Vec::new();
            for reference in references {
                // TODO this should match on subtypes too
                if reference.reference_type_id == *reference_type_id {
                    result.push(reference.clone());
                }
            }
            result
        }
    }

    /// Find and filter references that refer to the specified node.
    fn find_references(reference_map: &HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference_type_id: &Option<ReferenceTypeId>) -> Option<Vec<Reference>> {
        let node_references = reference_map.get(node_id);
        if node_references.is_some() {
            let node_references = node_references.as_ref().unwrap();
            let result = AddressSpace::filter_references_by_type(node_references, reference_type_id);
            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        } else {
            None
        }
    }

    /// Finds forward references from the specified node
    pub fn find_references_from(&self, node_id_from: &NodeId, reference_type_id: &Option<ReferenceTypeId>) -> Option<Vec<Reference>> {
        AddressSpace::find_references(&self.references, node_id_from, reference_type_id)
    }

    /// Finds inverse references, it those that point to the specified node
    pub fn find_references_to(&self, node_id_to: &NodeId, reference_type_id: &Option<ReferenceTypeId>) -> Option<Vec<Reference>> {
        AddressSpace::find_references(&self.inverse_references, node_id_to, reference_type_id)
    }

    /// Finds references for optionally forwards, inverse or both and return the references. The usize
    /// represents the index in the collection where the inverse references start (if applicable)
    pub fn find_references_by_direction(&self, node_id: &NodeId, browse_direction: BrowseDirection, reference_type_id: &Option<ReferenceTypeId>) -> (Vec<Reference>, usize) {
        let mut references = Vec::new();
        let inverse_ref_idx: usize;
        match browse_direction {
            BrowseDirection::Forward => {
                let forward_references = self.find_references_from(node_id, reference_type_id);
                if forward_references.is_some() {
                    references.append(&mut forward_references.unwrap());
                }
                inverse_ref_idx = references.len();
            }
            BrowseDirection::Inverse => {
                inverse_ref_idx = 0;
                let inverse_references = self.find_references_to(node_id, reference_type_id);
                if inverse_references.is_some() {
                    references.append(&mut inverse_references.unwrap());
                }
            }
            BrowseDirection::Both => {
                let forward_references = self.find_references_from(node_id, reference_type_id);
                if forward_references.is_some() {
                    references.append(&mut forward_references.unwrap());
                }
                inverse_ref_idx = references.len();
                let inverse_references = self.find_references_to(node_id, reference_type_id);
                if inverse_references.is_some() {
                    references.append(&mut inverse_references.unwrap());
                }
            }
        }
        (references, inverse_ref_idx)
    }


    //    fn make_oneway_reference(&mut self, node_id_from: &NodeId, node_id_to: &NodeId, reference_type_id: ReferenceTypeId) {
    //        AddressSpace::add_reference(&mut self.references, node_id_from, Reference::new(reference_type_id, node_id_to));
    //    }

    fn make_twoway_reference(&mut self, node_id_from: &NodeId, node_id_to: &NodeId, reference_type_id: ReferenceTypeId) {
        AddressSpace::add_reference(&mut self.references, node_id_from, Reference::new(reference_type_id, node_id_to));
        AddressSpace::add_reference(&mut self.inverse_references, node_id_to, Reference::new(reference_type_id, node_id_from));
    }

    pub fn add_organizes(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.make_twoway_reference(node_id_from, node_id_to, ReferenceTypeId::Organizes);
    }

    pub fn add_child(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.make_twoway_reference(node_id_from, node_id_to, ReferenceTypeId::HasChild);
    }

    pub fn add_property(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.make_twoway_reference(node_id_from, node_id_to, ReferenceTypeId::HasProperty);
    }
}
