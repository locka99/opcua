use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct ReferenceType {
    pub base: Base,
}

node_impl!(ReferenceType);

impl ReferenceType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, inverse_name: Option<LocalizedText>, symmetric: bool, is_abstract: bool) -> ReferenceType {
        // Mandatory
        let mut attributes = vec![
            (AttributeId::Symmetric, Variant::Boolean(symmetric)),
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        // Optional
        if let Some(inverse_name) = inverse_name {
            attributes.push((AttributeId::InverseName, Variant::from(inverse_name)));
        }
        ReferenceType {
            base: Base::new(NodeClass::ReferenceType, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn symmetric(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, Symmetric, Boolean)
    }

    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn inverse_name(&self) -> Option<LocalizedText> {
        let result = find_attribute_value_optional!(&self.base, InverseName, LocalizedText);
        if result.is_none() {
            None
        } else {
            Some(result.unwrap().as_ref().clone())
        }
    }
}
