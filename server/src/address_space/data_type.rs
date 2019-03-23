use opcua_types::service_types::DataTypeAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct DataType {
    base: Base,
}

node_impl!(DataType);

impl DataType {
    pub fn new<R, S, T>(node_id: &NodeId, browse_name: R, display_name: S, description: T, is_abstract: bool) -> DataType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              T: Into<LocalizedText>,
    {
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        DataType {
            base: Base::new(NodeClass::DataType, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: DataTypeAttributes) -> Self where S: Into<QualifiedName> {
        let mut node = Self::new(node_id, browse_name, "", "", false);
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
}
