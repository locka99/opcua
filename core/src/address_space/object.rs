use address_space::*;
use services::*;
use types::*;

pub struct Object {
    base_node: BaseNode,
}

node_impl!(Object, NodeClass::Object);
