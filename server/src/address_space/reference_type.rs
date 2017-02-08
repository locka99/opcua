use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceType {
    pub base: Base,
}

node_impl!(ReferenceType);

impl ReferenceType {
    pub fn new_node(node_id: &NodeId, browse_name: &str, display_name: &str, inverse_name: Option<LocalizedText>, symmetric: Boolean, is_abstract: Boolean) -> NodeType {
        NodeType::ReferenceType(ReferenceType::new(node_id, browse_name, display_name, inverse_name, symmetric, is_abstract))
    }

    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, inverse_name: Option<LocalizedText>, symmetric: Boolean, is_abstract: Boolean) -> ReferenceType {
        // Mandatory
        let mut attributes = vec![
            (AttributeId::Symmetric, Variant::Boolean(symmetric)),
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        // Optional
        if let Some(inverse_name) = inverse_name {
            attributes.push((AttributeId::InverseName, Variant::LocalizedText(inverse_name)));
        }
        let properties = vec![];

        ReferenceType {
            base: Base::new(NodeClass::ReferenceType, node_id, browse_name, display_name, attributes, properties),
        }
    }

    pub fn symmetric(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, Symmetric, Boolean)
    }

    pub fn is_abstract(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn inverse_name(&self) -> Option<LocalizedText> {
        find_attribute_value_optional!(&self.base, InverseName, LocalizedText)
    }
}
