//! Provides functionality to create an address space, find nodes, add nodes, change attributes
//! and values on nodes.

use std::result::Result;

use opcua_types::{NodeId, AttributeId, DataValue};
use opcua_types::status_code::StatusCode;

/// An attribute getter trait is used to obtain the datavalue associated with the particular attribute id
/// This allows server implementations to supply a value on demand, usually in response to a polling action
/// such as a monitored item in a subscription.
pub trait AttributeGetter {
    /// Returns some datavalue or none
    fn get(&mut self, node_id: NodeId, attribute_id: AttributeId) -> Result<Option<DataValue>, StatusCode>;
}

/// An implementation of attribute getter that can be easily constructed from a mutable function
pub struct AttrFnGetter<F> where F: FnMut(NodeId, AttributeId) -> Result<Option<DataValue>, StatusCode> + Send {
    getter: F
}

impl<F> AttributeGetter for AttrFnGetter<F> where F: FnMut(NodeId, AttributeId) -> Result<Option<DataValue>, StatusCode> + Send {
    fn get(&mut self, node_id: NodeId, attribute_id: AttributeId) -> Result<Option<DataValue>, StatusCode> {
        (self.getter)(node_id, attribute_id)
    }
}

impl<F> AttrFnGetter<F> where F: FnMut(NodeId, AttributeId) -> Result<Option<DataValue>, StatusCode> + Send {
    pub fn new(getter: F) -> AttrFnGetter<F> { AttrFnGetter { getter } }
}

// An attribute setter. Sets the value on the specified attribute
pub trait AttributeSetter {
    /// Sets the attribute on the specified node
    fn set(&mut self, node_id: NodeId, attribute_id: AttributeId, data_value: DataValue) -> Result<(), StatusCode>;
}

/// An implementation of attribute setter that can be easily constructed using a mutable function
pub struct AttrFnSetter<F> where F: FnMut(NodeId, AttributeId, DataValue) -> Result<(), StatusCode> + Send {
    setter: F
}

impl<F> AttributeSetter for AttrFnSetter<F> where F: FnMut(NodeId, AttributeId, DataValue) -> Result<(), StatusCode> + Send {
    fn set(&mut self, node_id: NodeId, attribute_id: AttributeId, data_value: DataValue) -> Result<(), StatusCode> {
        (self.setter)(node_id, attribute_id, data_value)
    }
}

impl<F> AttrFnSetter<F> where F: FnMut(NodeId, AttributeId, DataValue) -> Result<(), StatusCode> + Send {
    pub fn new(setter: F) -> AttrFnSetter<F> { AttrFnSetter { setter } }
}

/// This is a sanity saving macro that adds Node trait methods to all types that have a base
/// member.
macro_rules! node_impl {
    ( $node_struct:ident ) => {
        use opcua_types::*;
        use opcua_types::status_code::StatusCode;
        use opcua_types::service_types::NodeClass;
        use address_space::node::NodeType;

        impl Node for $node_struct {
            fn node_class(&self) -> NodeClass { self.base.node_class() }
            fn node_id(&self) -> NodeId { self.base.node_id() }
            fn browse_name(&self) -> QualifiedName { self.base.browse_name() }
            fn display_name(&self) -> LocalizedText { self.base.display_name() }
            fn description(&self) -> Option<LocalizedText> { self.base.description() }
            fn write_mask(&self) -> Option<WriteMask> { self.base.write_mask() }
            fn set_write_mask(&mut self, write_mask: WriteMask) { self.base.set_write_mask(write_mask) }
            fn user_write_mask(&self) -> Option<WriteMask> { self.base.user_write_mask() }
            fn set_user_write_mask(&mut self, write_mask: WriteMask) { self.base.set_user_write_mask(write_mask) }
            fn find_attribute(&self, attribute_id: AttributeId) -> Option<DataValue> { self.base.find_attribute(attribute_id) }
            fn set_attribute(&mut self, attribute_id: AttributeId, value: DataValue) -> Result<(), StatusCode> { self.base.set_attribute(attribute_id, value) }
        }

        impl Into<NodeType> for $node_struct {
            fn into(self) -> NodeType { NodeType::$node_struct(self) }
        }
    }
}

/// Macro that finds an attribute that is mandatory for the node type and returns its entry.
/// This macro will trigger a panic if an expected attribute isn't there.
macro_rules! find_attribute_value_mandatory {
    ( $sel:expr, $attribute_id: ident, $variant_type: ident ) => {
        {
            if let Some(result) = find_attribute_value_optional!($sel, $attribute_id, $variant_type) {
                result
            }
            else {
                panic!("Mandatory attribute {:?} is missing", AttributeId::$attribute_id);
            }
        }
    }
}

/// Macro that finds an optional attribute returning the attribute in a `Some`, or
/// `None` if the attribute does not exist.
macro_rules! find_attribute_value_optional {
    ( $sel:expr, $attribute_id: ident, $variant_type: ident ) => {
        {
            use opcua_types::AttributeId;
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
pub mod address_space;
pub mod base;
pub mod object;
pub mod variable;
pub mod method;
pub mod node;
pub mod reference_type;
pub mod object_type;
pub mod variable_type;
pub mod data_type;
pub mod view;

mod method_impls;

bitflags! {
    pub struct AccessLevel: u8 {
        const CURRENT_READ = 1;
        const CURRENT_WRITE = 2;
        // These can be uncommented if they become used
        // const HISTORY_READ = 4;
        // const HISTORY_WRITE = 8;
        // const SEMANTIC_CHANGE = 16;
        // const STATUS_WRITE = 32;
        // const TIMESTAMP_WRITE = 64;
    }
}

bitflags! {
    pub struct UserAccessLevel: u8 {
        const CURRENT_READ = 1;
        const CURRENT_WRITE = 2;
        // These can be uncommented if they become used
        // const HISTORY_READ = 4;
        // const HISTORY_WRITE = 8;
        // const STATUS_WRITE = 32;
        // const TIMESTAMP_WRITE = 64;
    }
}

pub mod types {
    pub use super::{AttrFnGetter, AttrFnSetter};
    pub use super::address_space::{AddressSpace, ReferenceDirection};
    pub use super::data_type::DataType;
    pub use super::object::Object;
    pub use super::variable::Variable;
    pub use super::method::Method;
    pub use super::reference_type::ReferenceType;
    pub use super::object_type::ObjectType;
    pub use super::variable_type::VariableType;
    pub use super::view::View;
    pub use super::node::{Node, NodeType};
}

pub use self::address_space::AddressSpace;
