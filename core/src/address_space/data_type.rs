use address_space::*;
use types::*;
use services::*;

pub struct DataType {
    base_node: BaseNode,
}

node_impl!(DataType, NodeClass::DataType);
