use std::sync::{Arc, Mutex};
use std::convert::Into;

use opcua_types::node_ids::DataTypeId;

use address_space::base::Base;
use address_space::node::Node;
use address_space::{AttributeGetter, AttributeSetter};
use address_space::{AccessLevel, UserAccessLevel};

#[derive(Debug)]
pub struct Variable {
    base: Base,
}

node_impl!(Variable);

impl Variable {
    pub fn new<V>(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, value: V) -> Variable where V: Into<Variant> {
        let value = DataValue::new(value);
        let data_type = value.value.as_ref().unwrap().data_type();
        if let Some(data_type) = data_type {
            Variable::new_data_value(node_id, browse_name, display_name, description, data_type, value)
        } else {
            panic!("Data type cannot be inferred from the value, use another constructor such as new_data_value")
        }
    }

    pub fn new_with_data_type<V>(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: V) -> Variable where V: Into<Variant> {
        Variable::new_data_value(node_id, browse_name, display_name, description, data_type, DataValue::new(value))
    }

    pub fn new_array(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue, dimensions: &[UInt32]) -> Variable {
        let mut variable = Variable::new_data_value(node_id, browse_name, display_name, description, data_type, value);
        variable.set_array_dimensions(dimensions);
        variable
    }

    /// Constructs a new variable with the specified id, name, type and value
    pub fn new_data_value(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue) -> Variable {
        // Mandatory
        let historizing = false;
        let access_level = AccessLevel::CURRENT_READ;
        let user_access_level = UserAccessLevel::CURRENT_READ;
        let mut attributes = vec![
            (AttributeId::UserAccessLevel, Variant::Byte(user_access_level.bits)),
            (AttributeId::AccessLevel, Variant::Byte(access_level.bits)),
            (AttributeId::DataType, Variant::new::<NodeId>(data_type.into())),
            (AttributeId::Historizing, Variant::Boolean(historizing))
        ];

        // Optional attributes can be added through functions
        //
        //    MinimumSamplingInterval
        //    ArrayDimensions

        // If the value is an array, then array dimensions and the value rank will be set
        let array_dimensions = if let Some(ref value) = value.value {
            // Get the
            match value {
                &Variant::Array(ref values) => vec![values.len() as UInt32],
                &Variant::MultiDimensionArray(ref values) => {
                    // Multidimensional arrays encode/decode dimensions with Int32 in Part 6, but arrayDimensions in Part 3
                    // wants them as UInt32. Go figure... So convert Int32 to UInt32
                    values.dimensions.iter().map(|v| *v as UInt32).collect::<Vec<UInt32>>()
                }
                _ => vec![]
            }
        } else {
            vec![]
        };
        attributes.push((AttributeId::ValueRank, Variant::Int32(array_dimensions.len() as Int32)));
        if !array_dimensions.is_empty() {
            attributes.push((AttributeId::ArrayDimensions, Variant::from_u32_array(&array_dimensions)));
        }

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
        let _ = self.base.set_attribute(AttributeId::Value, value);
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
        let _ = self.base.set_attribute_value(AttributeId::ArrayDimensions, Variant::from_u32_array(dimensions), &now, &now);
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

    /// Sets the variable's value but first test to see if it has changed. If the value has not
    /// changed the existing timestamps are preserved. If
    pub fn set_value_direct<V>(&mut self, now: &DateTime, value: V) where V: Into<Variant> {
        let mut data_value = self.value();

        let new_value = value.into();
        if let Some(ref existing_value) = data_value.value {
            if *existing_value == new_value {
                return;
            }
        }
        data_value.server_timestamp = Some(now.clone());
        data_value.server_picoseconds = Some(0);
        data_value.source_timestamp = Some(now.clone());
        data_value.source_picoseconds = Some(0);
        data_value.value = Some(new_value);
        self.set_value(data_value);
    }

    pub fn is_readable(&self) -> bool {
        self.access_level().contains(AccessLevel::CURRENT_READ)
    }

    pub fn is_writable(&self) -> bool {
        self.access_level().contains(AccessLevel::CURRENT_WRITE)
    }

    pub fn set_writable(&mut self, writable: bool) {
        let mut access_level = self.access_level();
        if writable {
            access_level.insert(AccessLevel::CURRENT_WRITE);
        } else {
            access_level.remove(AccessLevel::CURRENT_WRITE);
        }
        self.set_access_level(access_level);
    }

    pub fn set_access_level(&mut self, access_level: AccessLevel) {
        let _ = self.base.set_attribute(AttributeId::AccessLevel, DataValue::new(access_level.bits));
    }

    pub fn access_level(&self) -> AccessLevel {
        let bits = find_attribute_value_mandatory!(&self.base, AccessLevel, Byte);
        AccessLevel::from_bits_truncate(bits)
    }

    pub fn is_user_readable(&self) -> bool {
        self.user_access_level().contains(UserAccessLevel::CURRENT_READ)
    }

    pub fn is_user_writable(&self) -> bool {
        self.user_access_level().contains(UserAccessLevel::CURRENT_WRITE)
    }

    pub fn set_user_access_level(&mut self, user_access_level: UserAccessLevel) {
        let _ = self.base.set_attribute(AttributeId::UserAccessLevel, DataValue::new(user_access_level.bits));
    }

    pub fn user_access_level(&self) -> UserAccessLevel {
        let bits = find_attribute_value_mandatory!(&self.base, UserAccessLevel, Byte);
        UserAccessLevel::from_bits_truncate(bits)
    }

    pub fn value_rank(&self) -> Int32 {
        find_attribute_value_mandatory!(&self.base, ValueRank, Int32)
    }

    pub fn historizing(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, Historizing, Boolean)
    }
}