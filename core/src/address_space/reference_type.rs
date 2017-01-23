use address_space::*;
use types::*;
use services::*;

#[derive(Debug, Clone, PartialEq)]
pub enum Reference {
    HasProperty(NodeId),
    HasComponent(NodeId),
    HasTypeDefinition(NodeId),
}

pub struct ReferenceType {
    pub base: Base,
}

node_impl!(ReferenceType);

impl ReferenceType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, symmetric: bool, is_abstract: bool, inverse_name: Option<LocalizedText>) -> ReferenceType {
        let mut attrs = vec![
            Attribute::Symmetric(symmetric),
            Attribute::IsAbstract(is_abstract),
        ];
        if let Some(inverse_name) = inverse_name {
            attrs.push(Attribute::InverseName(inverse_name));
        }
        ReferenceType {
            base: Base::new(NodeClass::ReferenceType, node_id, browse_name, display_name, attrs),
        }
    }
}

// NodeClass::ReferenceType