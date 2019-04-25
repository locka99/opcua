use std::sync::{Arc, Mutex};
use std::convert::{Into, TryInto};

use opcua_types::node_ids::DataTypeId;

use crate::{
    callbacks::{AttributeGetter, AttributeSetter},
    address_space::{
        AccessLevel, UserAccessLevel,
        base::Base,
        node::{Node, NodeAttributes},
    },
};
use opcua_types::service_types::VariableAttributes;

/// This is a builder object for constructing variable nodes programmatically.
pub struct VariableBuilder {
    node: Variable
}

macro_rules! node_builder_impl {
    ( $node_builder_struct:ident ) => {
        impl $node_builder_struct {

            fn node_id(mut self, node_id: NodeId) -> Self {
                let _ = self.node.base.set_node_id(node_id);
                self
            }

            pub fn browse_name<V>(mut self, browse_name: V) -> Self where V: Into<QualifiedName> {
                let _ = self.node.base.set_browse_name(browse_name);
                self
            }

            pub fn display_name<V>(mut self, display_name: V) -> Self where V: Into<LocalizedText> {
                self.node.set_display_name(display_name.into());
                self
            }

            pub fn description<V>(mut self, description: V) -> Self where V: Into<LocalizedText>{
                self.node.set_description(description.into());
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
        }.node_id(node_id.clone())
    }

    pub fn is_valid(&self) -> bool {
        self.node.is_valid()
    }

    pub fn value<V>(mut self, value: V) -> Self where V: Into<Variant> {
        let _ = self.node.set_value(value);
        self
    }

    pub fn data_type<T>(mut self, data_type: T) -> Self where T: Into<NodeId> {
        self.node.set_data_type(data_type);
        self
    }

    pub fn historizing(mut self, historizing: bool) -> Self {
        self.node.set_historizing(historizing);
        self
    }

    pub fn access_level(mut self, access_level: AccessLevel) -> Self {
        self.node.set_access_level(access_level);
        self
    }

    pub fn user_access_level(mut self, user_access_level: UserAccessLevel) -> Self {
        self.node.set_user_access_level(user_access_level);
        self
    }

    pub fn value_rank(mut self, value_rank: i32) -> Self {
        self.node.set_value_rank(value_rank);
        self
    }

    pub fn array_dimensions(mut self, array_dimensions: &[u32]) -> Self {
        self.node.set_array_dimensions(array_dimensions);
        self
    }

    pub fn minimum_sampling_interval(mut self, minimum_sampling_interval: f64) -> Self {
        self.node.set_minimum_sampling_interval(minimum_sampling_interval);
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

// Note we use derivative builder macro so we can skip over the value getter / setter

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Variable {
    base: Base,
    data_type: NodeId,
    historizing: bool,
    value_rank: i32,
    value: DataValue,
    access_level: u8,
    user_access_level: u8,
    array_dimensions: Option<Vec<u32>>,
    minimum_sampling_interval: Option<f64>,
    #[derivative(Debug = "ignore")]
    value_setter: Option<Arc<Mutex<dyn AttributeSetter + Send>>>,
    #[derivative(Debug = "ignore")]
    value_getter: Option<Arc<Mutex<dyn AttributeGetter + Send>>>,
}

node_impl!(Variable);

impl Default for Variable {
    fn default() -> Self {
        let data_type: NodeId = DataTypeId::Int32.into();
        Variable {
            base: Base::new(NodeClass::Variable, &NodeId::null(), "", ""),
            data_type,
            historizing: false,
            value_rank: -1,
            value: Variant::Empty.into(),
            access_level: 0,
            user_access_level: 0,
            array_dimensions: None,
            minimum_sampling_interval: None,
            value_getter: None,
            value_setter: None,
        }
    }
}

impl NodeAttributes for Variable {
    fn get_attribute(&self, attribute_id: AttributeId, max_age: f64) -> Option<DataValue> {
        self.base.get_attribute(attribute_id, max_age).or_else(|| {
            if attribute_id == AttributeId::Value {
                Some(self.value())
            } else {
                match attribute_id {
                    // Mandatory attributes
                    AttributeId::DataType => Some(Variant::from(self.data_type())),
                    AttributeId::Historizing => Some(Variant::from(self.historizing())),
                    AttributeId::ValueRank => Some(Variant::from(self.value_rank())),
                    AttributeId::AccessLevel => Some(Variant::from(self.access_level().bits())),
                    AttributeId::UserAccessLevel => Some(Variant::from(self.user_access_level().bits())),
                    // Optional attributes
                    AttributeId::ArrayDimensions => {
                        if let Some(ref array_dimensions) = self.array_dimensions() {
                            Some(Variant::from(array_dimensions))
                        } else {
                            None
                        }
                    }
                    AttributeId::MinimumSamplingInterval => {
                        if let Some(minimum_sampling_interval) = self.minimum_sampling_interval() {
                            Some(Variant::from(minimum_sampling_interval))
                        } else {
                            None
                        }
                    }
                    _ => None
                }.map(|v| v.into())
            }
        })
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, value: Variant) -> Result<(), StatusCode> {
        if let Some(value) = self.base.set_attribute(attribute_id, value)? {
            match attribute_id {
                AttributeId::DataType => if let Variant::NodeId(v) = value {
                    self.set_data_type(*v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                },
                AttributeId::Historizing => if let Variant::Boolean(v) = value {
                    self.set_historizing(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                },
                AttributeId::ValueRank => if let Variant::Int32(v) = value {
                    self.set_value_rank(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                },
                AttributeId::Value => {
                    self.set_value(value);
                    Ok(())
                }
                AttributeId::AccessLevel => if let Variant::Byte(v) = value {
                    self.set_access_level(AccessLevel::from_bits_truncate(v));
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                },
                AttributeId::UserAccessLevel => if let Variant::Byte(v) = value {
                    self.set_user_access_level(UserAccessLevel::from_bits_truncate(v));
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                },
                AttributeId::ArrayDimensions => {
                    let array_dimensions: Result<Vec<u32>, ()> = value.try_into();
                    if let Ok(array_dimensions) = array_dimensions {
                        self.set_array_dimensions(&array_dimensions);
                        Ok(())
                    } else {
                        Err(StatusCode::BadTypeMismatch)
                    }
                },
                AttributeId::MinimumSamplingInterval => if let Variant::Double(v) = value {
                    self.set_minimum_sampling_interval(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                },
                _ => Err(StatusCode::BadAttributeIdInvalid)
            }
        } else {
            Ok(())
        }
    }
}

impl Variable {
    /// Creates a new variable. Note that data type, value rank and historizing are mandatory
    /// attributes of the Variable but not required by the constructor. The data type and value rank
    /// are inferred from the value. Historizing is not supported so is always false. If the
    /// inferred types for data type or value rank are wrong, they may be explicitly set, or
    /// call `new_data_value()` instead.
    pub fn new<R, S, V>(node_id: &NodeId, browse_name: R, display_name: S, value: V) -> Variable
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              V: Into<Variant>
    {
        let value = value.into();
        let data_type = value.data_type();
        if let Some(data_type) = data_type {
            Variable::new_data_value(node_id, browse_name, display_name, data_type, value)
        } else {
            panic!("Data type cannot be inferred from the value, use another constructor such as new_data_value")
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: VariableAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::ACCESS_LEVEL | AttributesMask::USER_ACCESS_LEVEL |
            AttributesMask::DATA_TYPE | AttributesMask::HISTORIZING | AttributesMask::VALUE | AttributesMask::VALUE_RANK;
        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(mandatory_attributes) {
            let mut node = Self::new_data_value(node_id, browse_name, attributes.display_name, attributes.data_type, attributes.value);
            node.set_value_rank(attributes.value_rank);
            node.set_historizing(attributes.historizing);
            node.set_access_level(AccessLevel::from_bits_truncate(attributes.access_level));
            node.set_user_access_level(UserAccessLevel::from_bits_truncate(attributes.user_access_level));

            if mask.contains(AttributesMask::DESCRIPTION) {
                node.set_description(attributes.description);
            }
            if mask.contains(AttributesMask::WRITE_MASK) {
                node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
            }
            if mask.contains(AttributesMask::USER_WRITE_MASK) {
                node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
            }
            if mask.contains(AttributesMask::ARRAY_DIMENSIONS) {
                node.set_array_dimensions(attributes.array_dimensions.unwrap().as_slice());
            }
            if mask.contains(AttributesMask::MINIMUM_SAMPLING_INTERVAL) {
                node.set_minimum_sampling_interval(attributes.minimum_sampling_interval);
            }
            Ok(node)
        } else {
            error!("Variable cannot be created from attributes - missing mandatory values");
            Err(())
        }
    }

    pub fn new_with_data_type<V>(node_id: &NodeId, browse_name: &str, display_name: &str, data_type: DataTypeId, value: V) -> Variable where V: Into<Variant> {
        Variable::new_data_value(node_id, browse_name, display_name, data_type, value)
    }

    /// Constructs a new variable with the specified id, name, type and value
    pub fn new_data_value<S, R, N, V>(node_id: &NodeId, browse_name: R, display_name: S, data_type: N, value: V) -> Variable
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              N: Into<NodeId>,
              V: Into<Variant>
    {
        let value = value.into();
        let array_dimensions = match value {
            Variant::Array(ref values) => Some(vec![values.len() as u32]),
            Variant::MultiDimensionArray(ref values) => {
                // Multidimensional arrays encode/decode dimensions with Int32 in Part 6, but arrayDimensions in Part 3
                // wants them as u32. Go figure... So convert Int32 to u32
                Some(values.dimensions.iter().map(|v| *v as u32).collect::<Vec<u32>>())
            }
            _ => None
        };

        let builder = VariableBuilder::new(node_id)
            .display_name(display_name)
            .browse_name(browse_name)
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
        if let Some(ref value_getter) = self.value_getter {
            let mut value_getter = value_getter.lock().unwrap();
            value_getter.get(&self.node_id(), AttributeId::Value, 0f64).unwrap().unwrap()
        } else {
            self.value.clone().into()
        }
    }

    /// Sets the variable's `Variant` value. The timestamps for the change are updated to now.
    pub fn set_value<V>(&mut self, value: V) where V: Into<Variant> {
        let value = value.into();
        // The value set to the value getter
        if let Some(ref value_setter) = self.value_setter {
            let mut value_setter = value_setter.lock().unwrap();
            let value = value.into();
            let data_value = if let Variant::DataValue(value) = value {
                // A variant containing a datavalue is treated as though that should be
                // the datavalue to set.
                *value
            } else {
                value.into()
            };
            let _ = value_setter.set(&self.node_id(), AttributeId::Value, data_value);
        } else {
            let now = DateTime::now();
            let value = if let Variant::DataValue(value) = value {
                value.value.unwrap_or(Variant::Empty)
            } else {
                value
            };
            self.set_value_direct(value, &now, &now);
        }
    }

    /// Sets the variable's `DataValue`
    pub fn set_value_direct<V>(&mut self, value: V, server_timestamp: &DateTime, source_timestamp: &DateTime) where V: Into<Variant> {
        self.value.value = Some(value.into());
        self.value.server_timestamp = Some(server_timestamp.clone());
        self.value.source_timestamp = Some(source_timestamp.clone());
    }

    /// Sets a getter function that will be called to get the value of this variable. Note
    /// you most likely want to set the corresponding setter too otherwise you will never get back
    /// the values you set otherwise.
    pub fn set_value_getter(&mut self, value_getter: Arc<Mutex<dyn AttributeGetter + Send>>) {
        self.value_getter = Some(value_getter);
    }

    /// Sets a setter function that will be called to set the value of this variable. Note
    /// you most likely want to set the corresponding getter too otherwise you will never get back
    /// the values you set otherwise.
    pub fn set_value_setter(&mut self, value_setter: Arc<Mutex<dyn AttributeSetter + Send>>) {
        self.value_setter = Some(value_setter);
    }

    /// Gets the minimum sampling interval, if the attribute was set
    pub fn minimum_sampling_interval(&self) -> Option<f64> {
        self.minimum_sampling_interval.clone()
    }

    /// Sets the minimum sampling interval
    ///
    /// Specifies in milliseconds how fast the server can reasonably sample the value for changes
    ///
    /// The value 0 means server is to monitor the value continuously. The value -1 means indeterminate.
    pub fn set_minimum_sampling_interval(&mut self, minimum_sampling_interval: f64) {
        self.minimum_sampling_interval = Some(minimum_sampling_interval);
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

    pub fn access_level(&self) -> AccessLevel {
        AccessLevel::from_bits_truncate(self.access_level)
    }

    pub fn set_access_level(&mut self, access_level: AccessLevel) {
        self.access_level = access_level.bits();
    }

    pub fn is_user_readable(&self) -> bool {
        self.user_access_level().contains(UserAccessLevel::CURRENT_READ)
    }

    pub fn is_user_writable(&self) -> bool {
        self.user_access_level().contains(UserAccessLevel::CURRENT_WRITE)
    }

    pub fn user_access_level(&self) -> UserAccessLevel {
        UserAccessLevel::from_bits_truncate(self.user_access_level)
    }

    pub fn set_user_access_level(&mut self, user_access_level: UserAccessLevel) {
        self.user_access_level = user_access_level.bits();
    }

    pub fn value_rank(&self) -> i32 {
        self.value_rank
    }

    pub fn set_value_rank(&mut self, value_rank: i32) {
        self.value_rank = value_rank;
    }

    pub fn historizing(&self) -> bool {
        self.historizing
    }

    pub fn set_historizing(&mut self, historizing: bool) {
        self.historizing = historizing;
    }

    pub fn array_dimensions(&self) -> Option<Vec<u32>> {
        self.array_dimensions.clone()
    }

    pub fn set_array_dimensions(&mut self, array_dimensions: &[u32]) {
        self.array_dimensions = Some(array_dimensions.to_vec());
    }

    pub fn data_type(&self) -> NodeId {
        self.data_type.clone()
    }

    pub fn set_data_type<T>(&mut self, data_type: T) where T: Into<NodeId> {
        self.data_type = data_type.into();
    }
}