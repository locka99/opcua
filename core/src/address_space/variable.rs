use address_space::*;
use types::*;
use services::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Variable {
    pub base: Base,
}

node_impl!(Variable);

impl Variable {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, value: &DataValue) -> Variable {
        // Mandatory
        let historizing = false;
        let access_level = 0;
        let user_access_level = 0;
        let value_rank = 0;
        let attributes = vec![
            Attribute::UserAccessLevel(user_access_level),
            Attribute::AccessLevel(access_level),
            Attribute::Value(value.clone()),
            Attribute::ValueRank(value_rank),
            Attribute::Historizing(historizing),
        ];

        // Optional
        // attrs.push(Attribute::MinimumSamplingInterval(0));
        // attrs.push(Attribute::ArrayDimensions(1));

        let references = vec![];
        let properties = vec![];
        Variable {
            base: Base::new(NodeClass::Variable, node_id, browse_name, display_name, attributes, references, properties),
        }
    }
}