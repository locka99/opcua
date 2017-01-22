use address_space::*;
use types::*;
use services::*;

pub struct View {
    base_node: BaseNode,
}

node_impl!(View, NodeClass::View);
