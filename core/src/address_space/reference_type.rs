use address_space::*;
use types::*;

pub enum Reference {
    HasProperty(NodeId),
    HasComponent(NodeId),
    HasTypeDefinition(NodeId),
}

pub struct ReferenceType {
    pub base_node: BaseNode,
    pub symmetric: bool,
    pub inverse_name: String,
    pub is_abstract: bool,
}

node_impl!(ReferenceType, NodeClass::ReferenceType);
