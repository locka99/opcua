use crate::address_space::base::Base;
use crate::address_space::node::Node;

#[derive(Debug)]
pub struct VariableType {
    pub base: Base,
}

node_impl!(VariableType);

impl VariableType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, is_abstract: bool, value_rank: i32) -> VariableType {
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

    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn value_rank(&self) -> i32 {
        find_attribute_value_mandatory!(&self.base, ValueRank, Int32)
    }
}