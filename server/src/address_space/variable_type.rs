use opcua_types::service_types::VariableTypeAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct VariableType {
    pub base: Base,
}

node_impl!(VariableType);

impl VariableType {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, data_type: NodeId, is_abstract: bool, value_rank: i32) -> VariableType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
            (AttributeId::DataType, Variant::from(data_type)),
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
            (AttributeId::ValueRank, Variant::Int32(value_rank)),
        ];
        // Optional
        // Attribute::Value(value),
        // Attribute::ArrayDimensions(value),

        VariableType {
            base: Base::new(NodeClass::VariableType, node_id, browse_name, display_name, attributes),
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: VariableTypeAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(AttributesMask::DISPLAY_NAME | AttributesMask::IS_ABSTRACT |
            AttributesMask::DATA_TYPE | AttributesMask::VALUE_RANK) {
            let mut node = Self::new(node_id, browse_name, attributes.display_name,
                                     attributes.data_type, attributes.is_abstract, attributes.value_rank);
            if mask.contains(AttributesMask::DESCRIPTION) {
                node.set_description(attributes.description);
            }
            if mask.contains(AttributesMask::WRITE_MASK) {
                node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
            }
            if mask.contains(AttributesMask::USER_WRITE_MASK) {
                node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
            }
            if mask.contains(AttributesMask::VALUE) {
                node.set_value(attributes.value);
            }
            if mask.contains(AttributesMask::ARRAY_DIMENSIONS) {
                node.set_array_dimensions(attributes.array_dimensions.unwrap().as_slice());
            }
            Ok(node)
        } else {
            error!("VariableType cannot be created from attributes - missing mandatory values");
            Err(())
        }
    }

    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn set_is_abstract(&mut self, is_abstract: bool) {
        let _ = self.set_attribute(AttributeId::IsAbstract, Variant::Boolean(is_abstract).into());
    }

    pub fn value_rank(&self) -> i32 {
        find_attribute_value_mandatory!(&self.base, ValueRank, Int32)
    }

    pub fn set_value_rank(&mut self, value_rank: i32) {
        let _ = self.set_attribute(AttributeId::ValueRank, Variant::from(value_rank).into());
    }

    pub fn set_array_dimensions(&mut self, array_dimensions: &[u32]) {
        let _ = self.set_attribute(AttributeId::ArrayDimensions, Variant::from(array_dimensions).into());
    }

    pub fn set_data_type<T>(&mut self, data_type: T) where T: Into<NodeId> {
        let node_id: NodeId = data_type.into();
        let _ = self.set_attribute(AttributeId::DataType, Variant::from(node_id).into());
    }

    pub fn set_value<V>(&mut self, value: V) where V: Into<DataValue> {
        let _ = self.set_attribute(AttributeId::Value, value.into());
    }
}