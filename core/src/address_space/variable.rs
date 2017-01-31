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
        let value_rank = -1;
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

        let properties = vec![];
        Variable {
            base: Base::new(NodeClass::Variable, node_id, browse_name, display_name, attributes, properties),
        }
    }

    pub fn access_level(&self) -> Byte {
        find_attribute_value_mandatory!(&self.base, AccessLevel);
    }

    pub fn user_access_level(&self) -> Byte {
        find_attribute_value_mandatory!(&self.base, UserAccessLevel);
    }

    pub fn value(&self) -> DataValue {
        find_attribute_value_mandatory!(&self.base, Value);
    }

    pub fn set_value(&mut self, value: DataValue) {
        self.base.set_attribute(AttributeId::Value, Attribute::Value(value));
    }

    pub fn value_rank(&self) -> Int32 {
        find_attribute_value_mandatory!(&self.base, ValueRank);
    }

    pub fn historizing(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, Historizing);
    }
}