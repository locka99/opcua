use std::collections::HashMap;

use opcua_core::services::*;
use opcua_core::types::*;

use address_space::*;
use server::*;

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

    pub fn node_id(&self) -> NodeId {
        self.as_node().node_id()
    }
}

#[derive(Debug, Clone)]
pub struct AddressSpace {
    pub node_map: HashMap<NodeId, NodeType>,
    pub references: HashMap<NodeId, Vec<Reference>>,
    pub inverse_references: HashMap<NodeId, Vec<Reference>>,
}

impl AddressSpace {
    pub fn new() -> AddressSpace {
        // Construct the Root folder and the top level nodes
        let mut address_space = AddressSpace {
            node_map: HashMap::new(),
            references: HashMap::new(),
            inverse_references: HashMap::new(),
        };
        address_space.add_default_nodes();
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

    pub fn insert(&mut self, node_type: NodeType) {
        let node_id = node_type.node_id();
        if self.node_exists(&node_id) {
            panic!("This node {:?} already exists", node_id);
        }
        self.node_map.insert(node_id, node_type);
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

    /// Adds a node as a child (organized by) another node. The type id says what kind of node the object
    /// should be, e.g. folder node or something else.
    pub fn add_organized_node(&mut self, node_id: &NodeId, browse_name: &str, display_name: &str, parent_node_id: &NodeId, node_type_id: ObjectTypeId) -> Result<NodeId, ()> {
        if self.node_exists(&node_id) {
            panic!("Node {:?} already exists", node_id);
        } else {
            // Add a relationship to the parent
            self.insert(Object::new_node(&node_id, browse_name, display_name, ""));
            self.add_organizes(&parent_node_id, &node_id);
            self.insert_reference(&node_id, &node_type_id.as_node_id(), ReferenceTypeId::HasTypeDefinition);
            Ok(node_id.clone())
        }
    }

    /// Adds a folder with a specified id
    pub fn add_folder_with_id(&mut self, node_id: &NodeId, browse_name: &str, display_name: &str, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        self.add_organized_node(node_id, browse_name, display_name, parent_node_id, ObjectTypeId::FolderType)
    }

    /// Adds a folder using a generated node id
    pub fn add_folder(&mut self, browse_name: &str, display_name: &str, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        self.add_folder_with_id(&NodeId::next_numeric(), browse_name, display_name, parent_node_id)
    }

    /// Adds a list of varables to the specified parent node
    pub fn add_variables(&mut self, variables: &Vec<Variable>, parent_node_id: &NodeId) -> Vec<Result<NodeId, ()>> {
        let mut result = Vec::with_capacity(variables.len());
        for variable in variables {
            result.push(self.add_variable(variable, parent_node_id));
        }
        result
    }

    /// Adds a single variable under the parent node
    pub fn add_variable(&mut self, variable: &Variable, parent_node_id: &NodeId) -> Result<NodeId, ()> {
        let node_id = variable.node_id();
        if !self.node_map.contains_key(&node_id) {
            self.add_organizes(&parent_node_id, &node_id);
            self.insert(NodeType::Variable(variable.clone()));
            Ok(node_id)
        } else {
            Err(())
        }
    }

    /// Adds a reference between one node and a target
    fn add_reference(reference_map: &mut HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference: Reference) {
        if reference_map.contains_key(node_id) {
            let mut references = reference_map.get_mut(node_id).unwrap();
            references.push(reference);
        } else {
            reference_map.insert(node_id.clone(), vec![reference]);
        }
    }

    /// This is a convenience method. It sets a value directly on a variable assuming the supplied
    /// node id exists in the address space and is a Variable node. The response is true if the
    /// value was set and false otherwise.
    pub fn set_variable_value(&mut self, node_id: &NodeId, value: Variant) -> bool {
        let node = self.find_node_mut(node_id);
        if node.is_none() {
            false
        } else {
            if let &mut NodeType::Variable(ref mut variable) = node.unwrap() {
                variable.set_value_direct(&DateTime::now(), value);
                true
            } else {
                false
            }
        }
    }

    fn reference_type_matches(&self, r1: ReferenceTypeId, r2: ReferenceTypeId, include_subtypes: bool) -> bool {
        if r1 == r2 {
            true
        } else if include_subtypes {
            // THIS IS AN UGLY HACK. The subtype code should really use walk down the hierchical types in the address space to figure this out
            match r1 {
                ReferenceTypeId::HierarchicalReferences => {
                    match r2 {
                        ReferenceTypeId::HierarchicalReferences | ReferenceTypeId::HasChild |
                        ReferenceTypeId::HasSubtype | ReferenceTypeId::Organizes |
                        ReferenceTypeId::Aggregates | ReferenceTypeId::HasProperty |
                        ReferenceTypeId::HasComponent | ReferenceTypeId::HasOrderedComponent |
                        ReferenceTypeId::HasEventSource | ReferenceTypeId::HasNotifier => {
                            true
                        }
                        _ => false
                    }
                }
                ReferenceTypeId::HasChild => {
                    match r2 {
                        ReferenceTypeId::Aggregates | ReferenceTypeId::HasComponent |
                        ReferenceTypeId::HasHistoricalConfiguration | ReferenceTypeId::HasProperty |
                        ReferenceTypeId::HasOrderedComponent | ReferenceTypeId::HasSubtype => {
                            true
                        }
                        _ => false
                    }
                }
                ReferenceTypeId::Aggregates => {
                    match r2 {
                        ReferenceTypeId::HasComponent | ReferenceTypeId::HasHistoricalConfiguration |
                        ReferenceTypeId::HasProperty | ReferenceTypeId::HasOrderedComponent => {
                            true
                        }
                        _ => false
                    }
                }
                ReferenceTypeId::HasComponent => {
                    r2 == ReferenceTypeId::HasOrderedComponent
                }
                ReferenceTypeId::HasEventSource => {
                    r2 == ReferenceTypeId::HasNotifier
                }
                _ => {
                    // TODO somehow work out subtypes, e.g. working back along inverse references
                    false
                }
            }
        } else {
            false
        }
    }

    fn filter_references_by_type(&self, references: &Vec<Reference>, reference_filter: Option<(ReferenceTypeId, bool)>) -> Vec<Reference> {
        if reference_filter.is_none() {
            references.clone()
        } else {
            // Filter by type
            let (reference_type_id, include_subtypes) = reference_filter.unwrap();
            let mut result = Vec::new();
            for reference in references {
                if self.reference_type_matches(reference_type_id, reference.reference_type_id, include_subtypes) {
                    result.push(reference.clone());
                }
            }
            result
        }
    }

    /// Find and filter references that refer to the specified node.
    fn find_references(&self, reference_map: &HashMap<NodeId, Vec<Reference>>, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        let node_references = reference_map.get(node_id);
        if node_references.is_some() {
            let node_references = node_references.as_ref().unwrap();
            let result = self.filter_references_by_type(node_references, reference_filter);
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
    pub fn find_references_from(&self, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        self.find_references(&self.references, node_id, reference_filter)
    }

    /// Finds inverse references, it those that point to the specified node
    pub fn find_references_to(&self, node_id: &NodeId, reference_filter: Option<(ReferenceTypeId, bool)>) -> Option<Vec<Reference>> {
        self.find_references(&self.inverse_references, node_id, reference_filter)
    }

    /// Finds references for optionally forwards, inverse or both and return the references. The usize
    /// represents the index in the collection where the inverse references start (if applicable)
    pub fn find_references_by_direction(&self, node_id: &NodeId, browse_direction: BrowseDirection, reference_filter: Option<(ReferenceTypeId, bool)>) -> (Vec<Reference>, usize) {
        let mut references = Vec::new();
        let inverse_ref_idx: usize;
        match browse_direction {
            BrowseDirection::Forward => {
                let forward_references = self.find_references_from(node_id, reference_filter);
                if forward_references.is_some() {
                    references.append(&mut forward_references.unwrap());
                }
                inverse_ref_idx = references.len();
            }
            BrowseDirection::Inverse => {
                inverse_ref_idx = 0;
                let inverse_references = self.find_references_to(node_id, reference_filter);
                if inverse_references.is_some() {
                    references.append(&mut inverse_references.unwrap());
                }
            }
            BrowseDirection::Both => {
                let forward_references = self.find_references_from(node_id, reference_filter);
                if forward_references.is_some() {
                    references.append(&mut forward_references.unwrap());
                }
                inverse_ref_idx = references.len();
                let inverse_references = self.find_references_to(node_id, reference_filter);
                if inverse_references.is_some() {
                    references.append(&mut inverse_references.unwrap());
                }
            }
        }
        (references, inverse_ref_idx)
    }

    /// Adds the standard nodeset to the address space
    pub fn add_default_nodes(&mut self) {
        super::generated::populate_address_space(self);
    }

    /// Sets values for nodes representing the server.
    pub fn add_server_nodes(&mut self, server_state: &ServerState) {
        let server_config = server_state.config.lock().unwrap();

        // Server/ (ServerType)
        self.set_variable_value(&VariableId::Server_NamespaceArray.as_node_id(), Variant::new_string_array(&server_state.namespaces));
        self.set_variable_value(&VariableId::Server_ServerArray.as_node_id(), Variant::new_string_array(&server_state.servers));
        self.set_variable_value(&VariableId::Server_ServerCapabilities_MaxArrayLength.as_node_id(), Variant::UInt32(server_config.max_array_length));
        self.set_variable_value(&VariableId::Server_ServerCapabilities_MaxStringLength.as_node_id(), Variant::UInt32(server_config.max_string_length));
        self.set_variable_value(&VariableId::Server_ServerCapabilities_MaxByteStringLength.as_node_id(), Variant::UInt32(server_config.max_byte_string_length));

        // State OPC UA Part 5 12.6, Valid states are
        //
        // Running = 0
        // Failed = 1
        // No configuration = 2
        // Suspended = 3
        // Shutdown = 4
        // Test = 5
        // Communication Fault = 6
        // Unknown = 7
        //     State (Server_ServerStatus_State)
        self.set_variable_value(&VariableId::Server_ServerStatus_State.as_node_id(), Variant::UInt32(0));

        // ServiceLevel - 0-255 worst to best quality of service
        self.set_variable_value(&VariableId::Server_ServiceLevel.as_node_id(), Variant::Byte(255));

        // Auditing - var
        // ServerCapabilities
        // ServerDiagnostics
        // VendorServiceInfo
        // ServerRedundancy
    }

    pub fn insert_reference(&mut self, node_id_from: &NodeId, node_id_to: &NodeId, reference_type_id: ReferenceTypeId) {
        if node_id_from == node_id_to {
            panic!("Node id from == node id to {:?}", node_id_from);
        }
        AddressSpace::add_reference(&mut self.references, node_id_from, Reference::new(reference_type_id, node_id_to));
        AddressSpace::add_reference(&mut self.inverse_references, node_id_to, Reference::new(reference_type_id, node_id_from));
    }

    pub fn set_object_type(&mut self, node_id: &NodeId, object_type: &ObjectTypeId) {
        self.insert_reference(node_id, &object_type.as_node_id(), ReferenceTypeId::HasTypeDefinition);
    }

    pub fn set_variable_type(&mut self, node_id: &NodeId, variable_type: &VariableTypeId) {
        self.insert_reference(node_id, &variable_type.as_node_id(), ReferenceTypeId::HasTypeDefinition);
    }

    pub fn set_variable_as_property_type(&mut self, node_id: &NodeId) {
        self.set_variable_type(node_id, &VariableTypeId::PropertyType);
    }

    pub fn add_has_component(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.insert_reference(node_id_from, node_id_to, ReferenceTypeId::HasComponent);
    }

    pub fn add_organizes(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.insert_reference(node_id_from, node_id_to, ReferenceTypeId::Organizes);
    }

    pub fn add_has_child(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.insert_reference(node_id_from, node_id_to, ReferenceTypeId::HasChild);
    }

    pub fn add_has_property(&mut self, node_id_from: &NodeId, node_id_to: &NodeId) {
        self.insert_reference(node_id_from, node_id_to, ReferenceTypeId::HasProperty);
    }
}
