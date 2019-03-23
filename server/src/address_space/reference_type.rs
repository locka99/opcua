use opcua_types::service_types::ReferenceTypeAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct ReferenceType {
    pub base: Base,
}

node_impl!(ReferenceType);

impl ReferenceType {
    pub fn new<R, S, T>(node_id: &NodeId, browse_name: R, display_name: S, description: T, inverse_name: Option<LocalizedText>, symmetric: bool, is_abstract: bool) -> ReferenceType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              T: Into<LocalizedText>,
    {
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

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: ReferenceTypeAttributes) -> Self
        where S: Into<QualifiedName> {
        let mut node = Self::new(node_id, browse_name, "", "", None, false, false);
        let mask = AttributesMask::from_bits_truncate(attributes.specified_attributes);
        if mask.contains(AttributesMask::DISPLAY_NAME) {
            node.base.set_display_name(attributes.display_name);
        }
        if mask.contains(AttributesMask::DESCRIPTION) {
            node.base.set_description(attributes.description);
        }
        if mask.contains(AttributesMask::WRITE_MASK) {
            node.base.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
        }
        if mask.contains(AttributesMask::USER_WRITE_MASK) {
            node.base.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
        }
        if mask.contains(AttributesMask::IS_ABSTRACT) {
            let _ = node.set_attribute(AttributeId::IsAbstract, Variant::Boolean(attributes.is_abstract).into());
        }
        if mask.contains(AttributesMask::SYMMETRIC) {
            let _ = node.set_attribute(AttributeId::Symmetric, Variant::Boolean(attributes.is_abstract).into());
        }
        if mask.contains(AttributesMask::INVERSE_NAME) {
            let _ = node.set_attribute(AttributeId::InverseName, Variant::from(attributes.inverse_name).into());
        }
        node
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
