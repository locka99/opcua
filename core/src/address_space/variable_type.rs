use address_space::*;
use types::*;
use services::*;

pub struct VariableType {
    pub base: Base,
}

node_impl!(VariableType);

impl VariableType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, is_abstract: bool, value_rank: Int32) -> VariableType {
        // Mandatory
        let attributes = vec![
            Attribute::IsAbstract(is_abstract),
            Attribute::ValueRank(value_rank),
        ];
        // Optional
        // Attribute::Value(value),
        // Attribute::ArrayDimensions(value),

        let references = vec![];
        let properties = vec![];
        VariableType {
            base: Base::new(NodeClass::VariableType, node_id, browse_name, display_name, attributes, references, properties),
        }
    }
}