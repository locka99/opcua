use address_space::*;
use services::*;
use types::*;

pub struct Object {
    base_node: BaseNode,
}

node_impl!(Object, NodeClass::Object);

impl Object {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str) -> Object {
        Object {
            base_node: BaseNode::new(node_id, browse_name, display_name),
        }
    }
}