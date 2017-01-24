use address_space::*;
use types::*;
use services::*;

pub struct ReferenceType {
    pub base: Base,
}

node_impl!(ReferenceType);

impl ReferenceType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, symmetric: bool, is_abstract: bool, inverse_name: Option<LocalizedText>) -> ReferenceType {
        // Mandatory
        let mut attributes = vec![
            Attribute::Symmetric(symmetric),
            Attribute::IsAbstract(is_abstract),
        ];
        // Optional
        if let Some(inverse_name) = inverse_name {
            attributes.push(Attribute::InverseName(inverse_name));
        }
        let references = vec![];
        let properties = vec![];
        ReferenceType {
            base: Base::new(NodeClass::ReferenceType, node_id, browse_name, display_name, attributes, references, properties),
        }
    }

    pub fn symmetric(&self) -> bool {
        find_attribute_mandatory!(&self.base, Symmetric);
    }

    pub fn is_abstract(&self) -> bool {
        find_attribute_mandatory!(&self.base, IsAbstract);
    }

    pub fn inverse_name(&self) -> Option<LocalizedText> {
        find_attribute_optional!(&self.base, InverseName);
    }
}
