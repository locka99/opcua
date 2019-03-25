use opcua_types::service_types::ObjectTypeAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct ObjectType {
    base: Base,
}

node_impl!(ObjectType);

impl ObjectType {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, is_abstract: bool) -> ObjectType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        ObjectType {
            base: Base::new(NodeClass::ObjectType, node_id, browse_name, display_name, attributes),
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: ObjectTypeAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(AttributesMask::DISPLAY_NAME | AttributesMask::IS_ABSTRACT) {
            let mut node = Self::new(node_id, browse_name, attributes.display_name, attributes.is_abstract);
            if mask.contains(AttributesMask::DESCRIPTION) {
                node.set_description(attributes.description);
            }
            if mask.contains(AttributesMask::WRITE_MASK) {
                node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
            }
            if mask.contains(AttributesMask::USER_WRITE_MASK) {
                node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
            }
            Ok(node)
        } else {
            error!("ObjectType cannot be created from attributes - missing mandatory values");
            Err(())
        }
    }

    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn set_is_abstract(&mut self, is_abstract: bool) {
        let _ = self.set_attribute(AttributeId::IsAbstract, Variant::Boolean(is_abstract).into());
    }
}