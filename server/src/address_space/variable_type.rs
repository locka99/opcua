use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub struct VariableType {
    pub base: Base,
}

node_impl!(VariableType);

impl VariableType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, is_abstract: bool, value_rank: Int32) -> VariableType {
        // Mandatory
        let attributes = vec![
            AttributeValue::IsAbstract(is_abstract),
            AttributeValue::ValueRank(value_rank),
        ];
        // Optional
        // Attribute::Value(value),
        // Attribute::ArrayDimensions(value),

        let properties = vec![];
        VariableType {
            base: Base::new(NodeClass::VariableType, node_id, browse_name, display_name, attributes, properties),
        }
    }

    pub fn is_abstract(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, IsAbstract);
    }

    pub fn value_rank(&self) -> Int32 {
        find_attribute_value_mandatory!(&self.base, ValueRank);
    }
}