use address_space::*;
use types::*;

pub struct Variable {
    pub base_node: BaseNode,
}

node_impl!(Variable, NodeClass::Variable);
