use std::sync::{Arc, Mutex};
use std::convert::Into;

use opcua_types::node_ids::DataTypeId;

use crate::address_space::{
    AttributeGetter, AttributeSetter,
    AccessLevel, UserAccessLevel,
    base::Base,
    node::Node,
};

/// This is a builder object for constructing variable nodes programmatically.
pub struct VariableBuilder {
    node: Variable
}

macro_rules! node_builder_impl {
    ( $node_builder_struct:ident ) => {
        impl $node_builder_struct {

            fn node_id(mut self, node_id: &NodeId) -> Self {
                let _ = self.node.base.set_node_id(node_id);
                self
            }

            pub fn display_name(mut self, display_name: &str) -> Self {
                let _ = self.node.base.set_display_name(LocalizedText::new("", display_name));
                self
            }

            pub fn browse_name(mut self, browse_name: &str) -> Self {
                let _ = self.node.base.set_browse_name(QualifiedName::new(0, browse_name));
                self
            }

            pub fn description(mut self, description: &str) -> Self {
                let _ = self.node.base.set_description(LocalizedText::new("", description));
                self
            }
        }
    }
}

node_builder_impl!(VariableBuilder);

impl VariableBuilder {
    pub fn new(node_id: &NodeId) -> VariableBuilder {
        VariableBuilder {
            node: Variable::default()
        }.node_id(node_id)
    }

    pub fn is_valid(&self) -> bool {
        self.node.is_valid()
    }

    pub fn value<V>(mut self, value: V) -> Self where V: Into<DataValue> {
        let _ = self.node.set_value(value);
        self
    }

    pub fn data_type(mut self, data_type: DataTypeId) -> Self {
        let node_id: NodeId = data_type.into();
        let _ = self.node.set_attribute(AttributeId::DataType, Variant::from(node_id).into());
        self
    }

    pub fn historizing(mut self, historizing: bool) -> Self {
        let _ = self.node.set_attribute(AttributeId::Historizing, Variant::Boolean(historizing).into());
        self
    }

    pub fn access_level(mut self, access_level: AccessLevel) -> Self {
        let _ = self.node.set_attribute(AttributeId::AccessLevel, Variant::Byte(access_level.bits).into());
        self
    }

    pub fn user_access_level(mut self, user_access_level: UserAccessLevel) -> Self {
        let _ = self.node.set_attribute(AttributeId::UserAccessLevel, Variant::Byte(user_access_level.bits).into());
        self
    }

    pub fn value_rank(mut self, value_rank: i32) -> Self {
        let _ = self.node.set_attribute(AttributeId::ValueRank, Variant::Int32(value_rank).into());
        self
    }

    pub fn array_dimensions(mut self, array_dimensions: &[u32]) -> Self {
        let _ = self.node.set_attribute(AttributeId::ArrayDimensions, Variant::from_u32_array(array_dimensions).into());
        self
    }

    pub fn minimum_sampling_interval(mut self, minimum_sampling_interval: i32) -> Self {
        let _ = self.node.set_attribute(AttributeId::MinimumSamplingInterval, Variant::Int32(minimum_sampling_interval).into());
        self
    }

    /// Yields the built variable. This function will panic if the variable is invalid.
    pub fn build(self) -> Variable {
        if self.is_valid() {
            self.node
        } else {
            panic!("The variable is not valid, node id = {:?}", self.node.base.node_id());
        }
    }
}

#[derive(Debug)]
pub struct Variable {
    base: Base,
}

node_impl!(Variable);

impl Default for Variable {
    fn default() -> Self {
        let data_type_node_id: NodeId = DataTypeId::Int32.into();
        Variable {
            base: Base::new(NodeClass::Variable, &NodeId::null(), "", "", "", vec![
                (AttributeId::UserAccessLevel, Variant::Byte(AccessLevel::CURRENT_READ.bits)),
                (AttributeId::AccessLevel, Variant::Byte(UserAccessLevel::CURRENT_READ.bits)),
                (AttributeId::DataType, Variant::from(data_type_node_id)),
                (AttributeId::Historizing, Variant::Boolean(false)),
                (AttributeId::ValueRank, Variant::Int32(-1)),
                (AttributeId::Value, Variant::Empty)
            ]),
        }
    }
}

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

    /// Constructs a new variable with the specified id, name, type and value
    pub fn new_data_value(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, data_type: DataTypeId, value: DataValue) -> Variable {
        let array_dimensions = if let Some(ref value) = value.value {
            // Get the
            match value {
                &Variant::Array(ref values) => Some(vec![values.len() as u32]),
                &Variant::MultiDimensionArray(ref values) => {
                    // Multidimensional arrays encode/decode dimensions with Int32 in Part 6, but arrayDimensions in Part 3
                    // wants them as u32. Go figure... So convert Int32 to u32
                    Some(values.dimensions.iter().map(|v| *v as u32).collect::<Vec<u32>>())
                }
                _ => None
            }
        } else {
            None
        };

        let builder = VariableBuilder::new(node_id)
            .display_name(display_name)
            .browse_name(browse_name)
            .description(description)
            .user_access_level(UserAccessLevel::CURRENT_READ)
            .access_level(AccessLevel::CURRENT_READ)
            .data_type(data_type)
            .historizing(false)
            .value(value);

        // Set the array info
        let builder = if let Some(array_dimensions) = array_dimensions {
            builder.value_rank(array_dimensions.len() as i32).array_dimensions(&array_dimensions)
        } else {
            builder.value_rank(-1)
        };
        builder.build()
    }

    pub fn is_valid(&self) -> bool {
        !self.base.node_id().is_null()
    }

    pub fn value(&self) -> DataValue {
        self.base.find_attribute(AttributeId::Value).unwrap()
    }

    /// Sets the variable's value
    pub fn set_value<V>(&mut self, value: V) where V: Into<DataValue> {
        // TODO if the value is an array or multi-dimensional array, should we
        //  set array dimensions / value rank?
        let _ = self.base.set_attribute(AttributeId::Value, value.into());
    }

    /// Sets the variable's value directly but first test to see if it has changed. If the value has not
    /// changed the existing timestamps are preserved.
    pub fn set_value_direct<V>(&mut self, value: V, source_timestamp: &DateTime, server_timestamp: &DateTime) where V: Into<Variant> {
        let _ = self.base.set_attribute(AttributeId::Value, DataValue::from((value.into(), source_timestamp, server_timestamp)));
    }

    /// Sets a getter function that will be called to get the value of this variable.
    pub fn set_value_getter(&mut self, getter: Arc<Mutex<dyn AttributeGetter + Send>>) {
        self.base.set_attribute_getter(AttributeId::Value, getter);
    }

    /// Sets a setter function that will be called to set the value of this variable. Note
    /// you most likely want to set the corresponding getter too otherwise you will never get back
    /// the values you set otherwise.
    pub fn set_value_setter(&mut self, setter: Arc<Mutex<dyn AttributeSetter + Send>>) {
        self.base.set_attribute_setter(AttributeId::Value, setter);
    }

    /// Gets the minimum sampling interval, if the attribute was set
    pub fn minimum_sampling_interval(&self) -> Option<i32> {
        find_attribute_value_optional!(&self.base, MinimumSamplingInterval, Int32)
    }

    /// Sets the minimum sampling interval
    ///
    /// Specifies in milliseconds how fast the server can reasonably sample the value for changes
    ///
    /// The value 0 means server is to monitor the value continuously. The value -1 means indeterminate.
    pub fn set_minimum_sampling_interval(&mut self, minimum_sampling_interval: i32) {
        let now = DateTime::now();
        let _ = self.base.set_attribute_value(AttributeId::MinimumSamplingInterval, Variant::Int32(minimum_sampling_interval), &now, &now);
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

    pub fn value_rank(&self) -> i32 {
        find_attribute_value_mandatory!(&self.base, ValueRank, Int32)
    }

    pub fn historizing(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, Historizing, Boolean)
    }

    pub fn array_dimensions(&self) -> Option<Vec<u32>> {
        if let Some(values) = find_attribute_value_optional!(&self.base, ArrayDimensions, Array) {
            // The expectation is that this Vec<Variant> is a non-zero Vec<u32>
            if values.is_empty() {
                panic!("Expecting array dimensions, got an empty array");
            } else {
                Some(values.iter().map(|v| {
                    if let Variant::UInt32(ref v) = v {
                        *v
                    } else {
                        panic!("Expecting array dimensions to be UInt32, but got a non UInt32");
                    }
                }).collect::<Vec<u32>>())
            }
        } else {
            None
        }
    }
}