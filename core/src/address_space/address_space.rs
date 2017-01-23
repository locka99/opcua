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
    Method(Method),
}


pub struct AddressSpace {
    pub node_map: HashMap<NodeId, NodeType>,
}

impl AddressSpace {
    pub fn new() -> AddressSpace {
        // Construct the Root folder and the top level nodes

        let root_node_id = ObjectId::RootFolder.as_node_id();
        let root_node = Object::new(&root_node_id, "Root", "Root");
        // HasTypeDefinition - FolderType

        let objects_node_id = ObjectId::ObjectsFolder.as_node_id();
        let objects_node = Object::new(&objects_node_id, "Objects", "Objects");
        // HasTypeDefinition - FolderType
        // Organizes - Top level server

        let types_node_id = ObjectId::TypesFolder.as_node_id();
        let types_node = Object::new(&types_node_id, "Types", "Types");
        // HasTypeDefinition - FolderType

        let views_node_id = ObjectId::ViewsFolder.as_node_id();
        let views_node = Object::new(&views_node_id, "Views", "Views");
        // HasTypeDefinition - FolderType

        let mut node_map  = HashMap::new();
        node_map.insert(root_node_id, NodeType::Object(root_node));
        node_map.insert(objects_node_id, NodeType::Object(objects_node));
        node_map.insert(types_node_id, NodeType::Object(types_node));
        node_map.insert(views_node_id, NodeType::Object(views_node));

        // TODO populate a node set
        AddressSpace {
            node_map: node_map,
        }
    }
}
