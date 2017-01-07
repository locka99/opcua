use address_space::*;
use types::*;

pub enum Reference {
    HasProperty(NodeId),
    HasComponent(NodeId),
    HasTypeDefinition(NodeId),
}

pub struct ReferenceType {
    base_node: BaseNode,
    symmetric: bool,
    inverse_name: String,
    is_abstract: bool,
}

node_impl!(ReferenceType, NodeClass::ReferenceType);
