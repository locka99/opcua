use opcua_types::service_types::ReferenceTypeAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct ReferenceType {
    pub base: Base,
}

node_impl!(ReferenceType);

impl ReferenceType {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, inverse_name: Option<LocalizedText>, symmetric: bool, is_abstract: bool) -> ReferenceType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
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
            base: Base::new(NodeClass::ReferenceType, node_id, browse_name, display_name, attributes),
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: ReferenceTypeAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(AttributesMask::DISPLAY_NAME | AttributesMask::IS_ABSTRACT | AttributesMask::SYMMETRIC) {
            let mut node = Self::new(node_id, browse_name, attributes.display_name, None, false, false);
            if mask.contains(AttributesMask::DESCRIPTION) {
                node.set_description(attributes.description);
            }
            if mask.contains(AttributesMask::WRITE_MASK) {
                node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
            }
            if mask.contains(AttributesMask::USER_WRITE_MASK) {
                node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
            }
            if mask.contains(AttributesMask::IS_ABSTRACT) {
                node.set_is_abstract(attributes.is_abstract);
            }
            if mask.contains(AttributesMask::SYMMETRIC) {
                node.set_symmetric(attributes.is_abstract);
            }
            if mask.contains(AttributesMask::INVERSE_NAME) {
                node.set_inverse_name(attributes.inverse_name);
            }
            Ok(node)
        } else {
            error!("ReferenceType cannot be created from attributes - missing mandatory values");
            Err(())
        }
    }

    pub fn symmetric(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, Symmetric, Boolean)
    }

    pub fn set_symmetric(&mut self, symmetric: bool) {
        let _ = self.set_attribute(AttributeId::Symmetric, Variant::Boolean(symmetric).into());
    }

    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn set_is_abstract(&mut self, is_abstract: bool) {
        let _ = self.set_attribute(AttributeId::IsAbstract, Variant::Boolean(is_abstract).into());
    }

    pub fn inverse_name(&self) -> Option<LocalizedText> {
        let result = find_attribute_value_optional!(&self.base, InverseName, LocalizedText);
        if result.is_none() {
            None
        } else {
            Some(result.unwrap().as_ref().clone())
        }
    }

    pub fn set_inverse_name(&mut self, inverse_name: LocalizedText) {
        let _ = self.set_attribute(AttributeId::InverseName, Variant::from(inverse_name).into());
    }
}
