use address_space::*;
use types::*;

pub struct ObjectType {
    base_node: BaseNode,
}

node_impl!(ObjectType, NodeClass::ObjectType);
