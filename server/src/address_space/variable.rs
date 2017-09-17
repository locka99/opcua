use std::sync::{Arc, Mutex};

use opcua_types::DataTypeId;

use address_space::base::Base;
use address_space::node::{Node, NodeType};
use address_space::{AttributeGetter, AttributeSetter};
use address_space::access_level;
use address_space::user_access_level;

#[derive(Debug)]
pub struct Variable {
    base: Base,
}

node_impl!(Variable);

impl Variable {
    pub fn new<T>(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: T) -> Variable where T: 'static + Into<Variant> {
        let value = DataValue::new(value);
        let data_type = value.value.as_ref().unwrap().data_type();
        Variable::new_data_value(node_id, browse_name, display_name, description, data_type, value)
    }

    pub fn new_node(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue) -> NodeType {
        NodeType::Variable(Variable::new_data_value(node_id, browse_name, display_name, description, data_type, value))
    }

    pub fn new_array(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue, dimensions: &[UInt32]) -> Variable {
        let mut variable = Variable::new_data_value(node_id, browse_name, display_name, description, data_type, value);
        variable.set_array_dimensions(dimensions);
        variable
    }

    pub fn new_array_node(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue, dimensions: &[UInt32]) -> NodeType {
        NodeType::Variable(Variable::new_array(node_id, browse_name, display_name, description, data_type, value, dimensions))
    }

    /// Constructs a new variable with the specified id, name, type and value
    pub fn new_data_value(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue) -> Variable {
        // Mandatory
        let historizing = false;
        let access_level = access_level::CURRENT_READ;
        let user_access_level = user_access_level::CURRENT_READ;
        let value_rank = -1;
        let attributes = vec![
            (AttributeId::UserAccessLevel, Variant::Byte(user_access_level)),
            (AttributeId::AccessLevel, Variant::Byte(access_level)),
            (AttributeId::DataType, Variant::new(data_type.as_node_id())),
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
        let _ = result.base.set_attribute(AttributeId::Value, value);
        result
    }

    pub fn value(&self) -> DataValue {
        self.base.find_attribute(AttributeId::Value).unwrap()
    }

    /// Sets the variable's value
    pub fn set_value(&mut self, value: DataValue) {
        self.base.set_attribute(AttributeId::Value, value);
    }

    pub fn set_value_getter(&mut self, getter: Arc<Mutex<AttributeGetter + Send>>) {
        self.base.set_attribute_getter(AttributeId::Value, getter);
    }

    pub fn set_value_setter(&mut self, setter: Arc<Mutex<AttributeSetter + Send>>) {
        self.base.set_attribute_setter(AttributeId::Value, setter);
    }

    /// Sets the array dimensions information
    ///
    /// Specifies the length of each dimension for an array value. 
    ///
    /// A value of 0 in any dimension means length of the dimension is variable.
    pub fn set_array_dimensions(&mut self, dimensions: &[UInt32]) {
        let now = DateTime::now();
        let _ = self.base.set_attribute_value(AttributeId::ValueRank, Variant::Int32(dimensions.len() as Int32), &now, &now);
        let _ = self.base.set_attribute_value(AttributeId::ArrayDimensions, Variant::new_u32_array(dimensions), &now, &now);
    }

    /// Sets the minimum sampling interval
    ///
    /// Specifies in milliseconds how fast the server can reasonably sample the value for changes
    ///
    /// The value 0 means server is to monitor the value continuously. The value -1 means indeterminate.
    pub fn set_minimum_sampling_interval(&mut self, minimum_sampling_interval: Int32) {
        let now = DateTime::now();
        let _ = self.base.set_attribute_value(AttributeId::MinimumSamplingInterval, Variant::Int32(minimum_sampling_interval), &now, &now);
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

    pub fn is_readable(&self) -> bool {
        (self.access_level() & access_level::CURRENT_READ) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.access_level() & access_level::CURRENT_WRITE) != 0
    }

    pub fn set_writable(&mut self) {
        let access_level = self.access_level() & access_level::CURRENT_WRITE;
        self.set_user_access_level(access_level);
    }

    pub fn set_access_level(&mut self, access_level: Byte) {
        let _ = self.base.set_attribute(AttributeId::AccessLevel, DataValue::new(access_level));
    }

    pub fn access_level(&self) -> Byte {
        find_attribute_value_mandatory!(&self.base, AccessLevel, Byte)
    }

    pub fn is_user_readable(&self) -> bool {
        (self.user_access_level() & user_access_level::CURRENT_READ) != 0
    }

    pub fn is_user_writable(&self) -> bool {
        (self.user_access_level() & user_access_level::CURRENT_WRITE) != 0
    }

    pub fn set_user_access_level(&mut self, user_access_level: Byte) {
        let _ = self.base.set_attribute(AttributeId::UserAccessLevel, DataValue::new(user_access_level));
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
