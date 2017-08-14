/// This is a sanity saving macro that adds Node trait methods to all types that have a base
/// member.
///

use std::sync::Arc;

use opcua_types::{NodeClass, NodeId, LocalizedText, QualifiedName, UInt32, AttributeId, DataValue};

pub trait AttributeGetter {
    fn get(&self, attribute_id: AttributeId, node_id: NodeId) -> Option<DataValue>;
}

pub trait AttributeSetter {
    fn set(&mut self, attribute_id: AttributeId, node_id: NodeId, data_value: DataValue);
}

/// Implemented by Base and all derived Node types. Functions that return a result in an Option
/// do so because the attribute is optional and not necessarily there.
pub trait Node {
    fn node_class(&self) -> NodeClass;
    fn node_id(&self) -> NodeId;
    fn browse_name(&self) -> QualifiedName;
    fn display_name(&self) -> LocalizedText;
    fn description(&self) -> Option<LocalizedText>;
    fn write_mask(&self) -> Option<UInt32>;
    fn user_write_mask(&self) -> Option<UInt32>;
    fn find_attribute(&self, attribute_id: AttributeId) -> Option<DataValue>;
    fn set_attribute_getter(&mut self, attribute_id: AttributeId, getter: Arc<Box<AttributeGetter + Send>>);
    fn set_attribute_setter(&mut self, attribute_id: AttributeId, setter: Arc<Box<AttributeSetter + Send>>);
}

macro_rules! node_impl {
    ( $node_struct:ty ) => {
        use opcua_types::*;
        impl Node for $node_struct {
            fn node_class(&self) -> NodeClass { self.base.node_class() }
            fn node_id(&self) -> NodeId { self.base.node_id() }
            fn browse_name(&self) -> QualifiedName { self.base.browse_name() }
            fn display_name(&self) -> LocalizedText { self.base.display_name() }
            fn description(&self) -> Option<LocalizedText> { self.base.description() }
            fn write_mask(&self) -> Option<UInt32> { self.base.write_mask() }
            fn user_write_mask(&self) -> Option<UInt32> { self.base.user_write_mask() }
            fn find_attribute(&self, attribute_id: AttributeId) -> Option<DataValue> { self.base.find_attribute(attribute_id) }
            fn set_attribute_getter(&mut self, attribute_id: AttributeId, getter: Arc<Box<AttributeGetter + Send>>) {
                self.base.set_attribute_getter(attribute_id, getter);
            }
            fn set_attribute_setter(&mut self, attribute_id: AttributeId, setter: Arc<Box<AttributeSetter + Send>>) {
                self.base.set_attribute_setter(attribute_id, setter);
            }
        }
    };
}

#[macro_export]
macro_rules! find_attribute_value_mandatory {
    ( $sel:expr, $attribute_id: ident, $variant_type: ident ) => {
        {
            let result = find_attribute_value_optional!($sel, $attribute_id, $variant_type);
            if result.is_some() {
                result.unwrap()
            }
            else {
                panic!("Mandatory attribute {:?} is missing", AttributeId::$attribute_id);
            }
        }
    }
}

#[macro_export]
macro_rules! find_attribute_value_optional {
    ( $sel:expr, $attribute_id: ident, $variant_type: ident ) => {
        {
            let attribute_id = AttributeId::$attribute_id;
            let data_value = $sel.find_attribute(attribute_id);

            let mut result = None;
            if let Some(data_value) = data_value {
                if let Some(value) = data_value.value {
                    if let Variant::$variant_type(value) = value {
                        result = Some(value);
                    }
                }
            }
            result
        }
    }
}

pub mod generated;

pub mod types {
    pub use address_space::address_space::AddressSpace;
    pub use address_space::data_type::DataType;
    pub use address_space::object::Object;
    pub use address_space::variable::Variable;
    pub use address_space::method::Method;
    pub use address_space::reference_type::ReferenceType;
    pub use address_space::object_type::ObjectType;
    pub use address_space::variable_type::VariableType;
    pub use address_space::view::View;
}

mod address_space;
mod base;
mod object;
mod variable;
mod method;
mod reference_type;
mod object_type;
mod variable_type;
mod data_type;
mod view;

pub use self::address_space::*;
pub use self::base::*;
pub use self::object::*;
pub use self::variable::*;
pub use self::method::*;
pub use self::reference_type::*;
pub use self::object_type::*;
pub use self::variable_type::*;
pub use self::data_type::*;
pub use self::view::*;
