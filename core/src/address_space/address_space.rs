use std::collections::HashMap;

use services::*;
use address_space::{self, Node};
use types::*;

pub struct AddressSpace {
    node_map: HashMap<NodeId, Box<Node>>,
}

impl AddressSpace {
    pub fn new() -> AddressSpace {
        let root_node_id = NodeId::from_object_id(ObjectId::RootFolder);
        let root_node = address_space::Object::new(&root_node_id, "", "");
        let node_map = HashMap::new();
        node_map.insert(root_node_id, Box::new(root_node));
        // TODO populate a node set
        AddressSpace {
            node_map: node_map,
        }
    }
}
