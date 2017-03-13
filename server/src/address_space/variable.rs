use opcua_core::types::{DataTypeId};

use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Variable {
    pub base: Base,
}

node_impl!(Variable);

impl Variable {
    pub fn new_node(node_id: &NodeId, browse_name: &str, display_name: &str, data_type: &DataTypeId, value: DataValue) -> NodeType {
        NodeType::Variable(Variable::new(node_id, browse_name, display_name, data_type, value))
    }

    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, data_type: &DataTypeId, value: DataValue) -> Variable {
        // Mandatory
        let historizing = false;
        let access_level = 0;
        let user_access_level = 0;
        let value_rank = -1; // TODO if value is an array, maybe this and array dimensions should be explicitly set
        let attributes = vec![
            (AttributeId::UserAccessLevel, Variant::Byte(user_access_level)),
            (AttributeId::AccessLevel, Variant::Byte(access_level)),
            (AttributeId::DataType, Variant::NodeId(data_type.as_node_id())),
            (AttributeId::ValueRank, Variant::Int32(value_rank)),
            (AttributeId::Historizing, Variant::Boolean(historizing)),
        ];

        // Optional
        // attrs.push(Attribute::MinimumSamplingInterval(0));
        // attrs.push(Attribute::ArrayDimensions(1));
        let mut result = Variable {
            base: Base::new(NodeClass::Variable, node_id, browse_name, display_name, attributes, ),
        };
        result.base.set_attribute(AttributeId::Value, value);
        result
    }

    pub fn new_array_node(node_id: &NodeId, browse_name: &str, display_name: &str, data_type: &DataTypeId, value: DataValue, dimensions: &[Int32]) -> NodeType {
        NodeType::Variable(Variable::new_array(node_id, browse_name, display_name, data_type, value, dimensions))
    }

    pub fn new_array(node_id: &NodeId, browse_name: &str, display_name: &str, data_type: &DataTypeId, value: DataValue, dimensions: &[Int32]) -> Variable {
        let mut variable = Variable::new(node_id, browse_name, display_name, data_type, value);
        // An array has a value rank equivalent to the number of dimensions and an ArrayDimensions array
        let now = DateTime::now();
        variable.base.set_attribute_value(AttributeId::ValueRank, Variant::Int32(dimensions.len() as Int32), &now, &now);
        variable.base.set_attribute_value(AttributeId::ArrayDimensions, Variant::from_i32_array(dimensions), &now, &now);
        variable
    }

    pub fn value(&self) -> DataValue {
        if let &Some(ref attribute) = &self.base.attributes[Base::attribute_idx(AttributeId::Value)] {
            attribute.clone()
        } else {
            panic!("Variable value is missing");
        }
    }

    /// Sets the variable's value
    pub fn set_value(&mut self, value: DataValue) {
        // Value is directly set - it's a datavalue
        self.base.attributes[Base::attribute_idx(AttributeId::Value)] = Some(value);
    }

    /// Sets the variables value directly, updating the timestamp
    pub fn set_value_direct(&mut self, now: &DateTime, value: Variant) {
        let mut data_value = self.value();
        data_value.server_timestamp = Some(now.clone());
        data_value.server_picoseconds = Some(0);
        data_value.source_timestamp = Some(now.clone());
        data_value.source_picoseconds = Some(0);
        data_value.value = Some(value);
        self.set_value(data_value);
    }

    pub fn access_level(&self) -> Byte {
        find_attribute_value_mandatory!(&self.base, AccessLevel, Byte)
    }

    pub fn user_access_level(&self) -> Byte {
        find_attribute_value_mandatory!(&self.base, UserAccessLevel, Byte)
    }

    pub fn value_rank(&self) -> Int32 {
        find_attribute_value_mandatory!(&self.base, ValueRank, Int32)
    }

    pub fn historizing(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, Historizing, Boolean)
    }
}