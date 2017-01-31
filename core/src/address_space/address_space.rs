use std::collections::HashMap;

use address_space::*;
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
        let root_node_id = AddressSpace::root_folder_id();
        let root_node = Object::new(&root_node_id, "Root", "Root");

        let objects_node_id = AddressSpace::objects_folder_id();
        let objects_node = Object::new(&objects_node_id, "Objects", "Objects");

        let types_node_id = AddressSpace::types_folder_id();
        let types_node = Object::new(&types_node_id, "Types", "Types");

        let views_node_id = AddressSpace::views_folder_id();
        let views_node = Object::new(&views_node_id, "Views", "Views");

        address_space.insert(&root_node_id, NodeType::Object(root_node));
        address_space.insert(&objects_node_id, NodeType::Object(objects_node));
        address_space.insert(&types_node_id, NodeType::Object(types_node));
        address_space.insert(&views_node_id, NodeType::Object(views_node));

        address_space.add_organizes(&root_node_id, &objects_node_id);
        address_space.add_organizes(&root_node_id, &types_node_id);
        address_space.add_organizes(&root_node_id, &views_node_id);

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

    pub fn add_folder(&mut self, browse_name: &str, display_name: &str, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        let node_id = NodeId::next_numeric();

        // Add a relationship to the parent
        self.add_organizes(&parent_node_id, &node_id);

        let folder_object = Object::new(&node_id, browse_name, display_name);
        self.make_twoway_reference(&folder_object.node_id(), &ObjectTypeId::FolderType.as_node_id(), ReferenceTypeId::HasTypeDefinition);
        self.insert(&node_id, NodeType::Object(folder_object));

        Ok(node_id)
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

    fn filter_references_by_type(references: &Vec<Reference>, reference_type_id: Option<ReferenceTypeId>) -> Vec<Reference> {
        if reference_type_id.is_none() {
            references.clone()
        } else {
            // Filter by type
            let reference_type_id = reference_type_id.unwrap();
            let mut result = Vec::new();
            for reference in references {
                // TODO this should match on subtypes too
                if reference.reference_type_id == reference_type_id {
                    result.push(reference.clone());
                }
            }
            result
        }
    }

    fn find_references(reference_map: &HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference_type_id: Option<ReferenceTypeId>) -> Option<Vec<Reference>> {
        let node_references = reference_map.get(node_id);
        if node_references.is_some() {
            let node_references = node_references.as_ref().unwrap();
            let result = AddressSpace::filter_references_by_type(node_references, reference_type_id);
            if result.len() != 0 {
                Some(result)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn find_references_from(&self, node_id_from: &NodeId, reference_type_id: Option<ReferenceTypeId>) -> Option<Vec<Reference>> {
        AddressSpace::find_references(&self.references, node_id_from, reference_type_id)
    }

    pub fn find_references_to(&self, node_id_to: &NodeId, reference_type_id: Option<ReferenceTypeId>) -> Option<Vec<Reference>> {
        AddressSpace::find_references(&self.inverse_references, node_id_to, reference_type_id)
    }

    fn make_oneway_reference(&mut self, node_id_from: &NodeId, node_id_to: &NodeId, reference_type_id: ReferenceTypeId) {
        AddressSpace::add_reference(&mut self.references, node_id_from, Reference::new(reference_type_id, node_id_to));
    }

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
