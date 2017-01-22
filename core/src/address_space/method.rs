use address_space::*;
use types::*;
use services::*;

pub struct Method {
    base_node: BaseNode,
}

node_impl!(Method, NodeClass::Method);
