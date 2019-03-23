use opcua_types::service_types::VariableTypeAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct VariableType {
    pub base: Base,
}

node_impl!(VariableType);

impl VariableType {
    pub fn new<R, S, T>(node_id: &NodeId, browse_name: R, display_name: S, description: T, is_abstract: bool, value_rank: i32) -> VariableType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              T: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
            (AttributeId::ValueRank, Variant::Int32(value_rank)),
        ];
        // Optional
        // Attribute::Value(value),
        // Attribute::ArrayDimensions(value),

        VariableType {
            base: Base::new(NodeClass::VariableType, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: VariableTypeAttributes) -> Self where S: Into<QualifiedName> {
        let mut node = Self::new(node_id, browse_name, "", "", false, -1);
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
        if mask.contains(AttributesMask::VALUE) {
            let _ = node.set_attribute(AttributeId::Value, attributes.value.into());
        }
        if mask.contains(AttributesMask::DATA_TYPE) {
            let _ = node.set_attribute(AttributeId::DataType, Variant::from(attributes.data_type).into());
        }
        if mask.contains(AttributesMask::VALUE_RANK) {
            let _ = node.set_attribute(AttributeId::ValueRank, Variant::from(attributes.value_rank).into());
        }
        if mask.contains(AttributesMask::ARRAY_DIMENSIONS) {
            let _ = node.set_attribute(AttributeId::ValueRank, Variant::from(attributes.array_dimensions.unwrap()).into());
        }
        if mask.contains(AttributesMask::IS_ABSTRACT) {
            let _ = node.set_attribute(AttributeId::IsAbstract, Variant::Boolean(attributes.is_abstract).into());
        }
        node
    }
    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn value_rank(&self) -> i32 {
        find_attribute_value_mandatory!(&self.base, ValueRank, Int32)
    }
}