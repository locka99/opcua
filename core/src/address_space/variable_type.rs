use address_space::*;
use types::*;
use services::*;

pub struct VariableType {
    pub base_node: BaseNode,
}

node_impl!(VariableType, NodeClass::VariableType);
