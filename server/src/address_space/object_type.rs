use crate::address_space::{base::Base, node::Node};
use opcua_types::service_types::ObjectTypeAttributes;

#[derive(Debug)]
pub struct ObjectType {
    base: Base,
}

node_impl!(ObjectType);

impl ObjectType {
    pub fn new<R, S, T>(node_id: &NodeId, browse_name: R, display_name: S, description: T, is_abstract: bool) -> ObjectType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              T: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        ObjectType {
            base: Base::new(NodeClass::ObjectType, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn from_attributes(node_id: &NodeId, browse_name: &QualifiedName, attributes: ObjectTypeAttributes) -> Self {
        let mut node = Self::new(node_id, browse_name.name.as_ref(), "", "", false);
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
        node
    }

    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }
}