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
        let mut root_node = Object::new(&root_node_id, "Root", "Root");

        let objects_node_id = ObjectId::ObjectsFolder.as_node_id();
        let objects_node = Object::new(&objects_node_id, "Objects", "Objects");
        // Organizes - Top level server

        let types_node_id = ObjectId::TypesFolder.as_node_id();
        let types_node = Object::new(&types_node_id, "Types", "Types");

        let views_node_id = ObjectId::ViewsFolder.as_node_id();
        let views_node = Object::new(&views_node_id, "Views", "Views");

        root_node.add_child(&objects_node_id);
        root_node.add_child(&types_node_id);
        root_node.add_child(&views_node_id);

        let mut node_map = HashMap::new();
        node_map.insert(root_node_id, NodeType::Object(root_node));
        node_map.insert(objects_node_id, NodeType::Object(objects_node));
        node_map.insert(types_node_id, NodeType::Object(types_node));
        node_map.insert(views_node_id, NodeType::Object(views_node));

        // TODO populate a node set
        AddressSpace {
            node_map: node_map,
        }
    }

    pub fn find(&self, node_id: &NodeId) -> Option<&NodeType> {
        if self.node_map.contains_key(node_id) {
            self.node_map.get(node_id)
        }
        else {
            None
        }
    }
}
