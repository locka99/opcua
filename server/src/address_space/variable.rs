use std;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use opcua_types::DataTypeId;

use address_space::{Base, Node, NodeType, AttributeGetter, AttributeSetter};

#[derive(Debug)]
pub struct Variable {
    base: Base,
}

node_impl!(Variable);

impl Variable {
    pub fn new_node(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue) -> NodeType {
        NodeType::Variable(Variable::new(node_id, browse_name, display_name, description, data_type, value))
    }

    pub fn new_array_node(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue, dimensions: &[UInt32]) -> NodeType {
        NodeType::Variable(Variable::new_array(node_id, browse_name, display_name, description, data_type, value, dimensions))
    }

    pub fn new_array(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue, dimensions: &[UInt32]) -> Variable {
        let mut variable = Variable::new(node_id, browse_name, display_name, description, data_type, value);
        variable.set_array_dimensions(dimensions);
        variable
    }

    pub fn new_bool(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: Boolean) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::Boolean, DataValue::new(Variant::Boolean(value)))
    }

    pub fn new_byte(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: Byte) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::Byte, DataValue::new(Variant::Byte(value)))
    }

    pub fn new_sbyte(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: SByte) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::SByte, DataValue::new(Variant::SByte(value)))
    }

    pub fn new_i16(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: Int16) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::Int16, DataValue::new(Variant::Int16(value)))
    }

    pub fn new_u16(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: UInt16) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::UInt16, DataValue::new(Variant::UInt16(value)))
    }

    pub fn new_i32(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: Int32) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::Int32, DataValue::new(Variant::Int32(value)))
    }

    pub fn new_u32(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: UInt32) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::UInt32, DataValue::new(Variant::UInt32(value)))
    }

    pub fn new_i64(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: Int64) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::Int64, DataValue::new(Variant::Int64(value)))
    }

    pub fn new_u64(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: UInt64) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::UInt64, DataValue::new(Variant::UInt64(value)))
    }

    pub fn new_float(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: Float) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::Float, DataValue::new(Variant::Float(value)))
    }

    pub fn new_double(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: Double) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::Double, DataValue::new(Variant::Double(value)))
    }

    pub fn new_string(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: &str) -> Variable {
        Variable::new(node_id, browse_name, display_name, description, DataTypeId::String, DataValue::new(Variant::String(UAString::from_str(value))))
    }

    /// Constructs a new variable with the specified id, name, type and value
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue) -> Variable {
        // Mandatory
        let historizing = false;
        let access_level = 0;
        let user_access_level = 0;
        let value_rank = -1;
        let attributes = vec![
            (AttributeId::UserAccessLevel, Variant::Byte(user_access_level)),
            (AttributeId::AccessLevel, Variant::Byte(access_level)),
            (AttributeId::DataType, Variant::new_node_id(data_type.as_node_id())),
            (AttributeId::ValueRank, Variant::Int32(value_rank)),
            (AttributeId::Historizing, Variant::Boolean(historizing))
        ];

        // Optional attributes can be added through functions
        //
        //    MinimumSamplingInterval
        //    ArrayDimensions

        let mut result = Variable {
            base: Base::new(NodeClass::Variable, node_id, browse_name, display_name, description, attributes),
        };
        result.base.set_attribute(AttributeId::Value, value);
        result
    }

    pub fn value(&self) -> DataValue {
        self.base.find_attribute(AttributeId::Value).unwrap()
    }

    /// Sets the variable's value
    pub fn set_value(&mut self, value: DataValue) {
        self.base.set_attribute(AttributeId::Value, value);
    }

    //pub fn set_value_getter(&mut self, getter: Arc<Box<AttributeGetter + Send>>) {
    //    self.base.set_attribute_getter(AttributeId::Value, getter);
    //}

    //pub fn set_value_setter(&mut self, setter: Arc<Box<AttributeSetter + Send>>) {
    //    self.base.set_attribute_setter(AttributeId::Value, setter);
    //}

    /// Sets the array dimensions information
    ///
    /// Specifies the length of each dimension for an array value. 
    ///
    /// A value of 0 in any dimension means length of the dimension is variable.
    pub fn set_array_dimensions(&mut self, dimensions: &[UInt32]) {
        let now = DateTime::now();
        self.base.set_attribute_value(AttributeId::ValueRank, Variant::Int32(dimensions.len() as Int32), &now, &now);
        self.base.set_attribute_value(AttributeId::ArrayDimensions, Variant::new_u32_array(dimensions), &now, &now);
    }

    /// Sets the minimum sampling interval
    ///
    /// Specifies in milliseconds how fast the server can reasonably sample the value for changes
    ///
    /// The value 0 means server is to monitor the value continuously. The value -1 means indeterminate.
    pub fn set_minimum_sampling_interval(&mut self, minimum_sampling_interval: Int32) {
        let now = DateTime::now();
        self.base.set_attribute_value(AttributeId::MinimumSamplingInterval, Variant::Int32(minimum_sampling_interval), &now, &now);
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