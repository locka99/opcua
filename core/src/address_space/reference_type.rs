use address_space::*;
use types::*;
use services::*;

#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceType {
    pub base: Base,
}

node_impl!(ReferenceType);

impl ReferenceType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, inverse_name: Option<LocalizedText>, symmetric: Boolean, is_abstract: Boolean) -> ReferenceType {
        // Mandatory
        let mut attributes = vec![
            AttributeValue::Symmetric(symmetric),
            AttributeValue::IsAbstract(is_abstract),
        ];
        // Optional
        if let Some(inverse_name) = inverse_name {
            attributes.push(AttributeValue::InverseName(inverse_name));
        }
        let properties = vec![];

        ReferenceType {
            base: Base::new(NodeClass::ReferenceType, node_id, browse_name, display_name, attributes, properties),
        }
    }

    pub fn symmetric(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, Symmetric);
    }

    pub fn is_abstract(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, IsAbstract);
    }

    pub fn inverse_name(&self) -> Option<LocalizedText> {
        find_attribute_value_optional!(&self.base, InverseName);
    }
}
