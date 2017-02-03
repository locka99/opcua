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
            AttributeValue::UserAccessLevel(user_access_level),
            AttributeValue::AccessLevel(access_level),
            AttributeValue::Value(value.clone()),
            AttributeValue::ValueRank(value_rank),
            AttributeValue::Historizing(historizing),
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

    /// Sets the variable's value
    pub fn set_value(&mut self, value: DataValue, server_timestamp: &DateTime, source_timestamp: &DateTime) -> Result<(), ()> {
        self.base.update_attribute_value(AttributeId::Value, AttributeValue::Value(value), server_timestamp, source_timestamp)
    }

    pub fn value_rank(&self) -> Int32 {
        find_attribute_value_mandatory!(&self.base, ValueRank);
    }

    pub fn historizing(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, Historizing);
    }
}