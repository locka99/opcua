//! Provides functionality to create an address space, find nodes, add nodes, change attributes
//! and values on nodes.

use std::result::Result;

use opcua_types::{NodeId, AttributeId, DataValue};
use opcua_types::status_code::StatusCode;

use crate::callbacks::{AttributeGetter, AttributeSetter};

/// An implementation of attribute getter that can be easily constructed from a mutable function
pub struct AttrFnGetter<F> where F: FnMut(&NodeId, AttributeId, f64) -> Result<Option<DataValue>, StatusCode> + Send {
    getter: F
}

impl<F> AttributeGetter for AttrFnGetter<F> where F: FnMut(&NodeId, AttributeId, f64) -> Result<Option<DataValue>, StatusCode> + Send {
    fn get(&mut self, node_id: &NodeId, attribute_id: AttributeId, max_age: f64) -> Result<Option<DataValue>, StatusCode> {
        (self.getter)(node_id, attribute_id, max_age)
    }
}

impl<F> AttrFnGetter<F> where F: FnMut(&NodeId, AttributeId, f64) -> Result<Option<DataValue>, StatusCode> + Send {
    pub fn new(getter: F) -> AttrFnGetter<F> { AttrFnGetter { getter } }
}

/// An implementation of attribute setter that can be easily constructed using a mutable function
pub struct AttrFnSetter<F> where F: FnMut(&NodeId, AttributeId, DataValue) -> Result<(), StatusCode> + Send {
    setter: F
}

impl<F> AttributeSetter for AttrFnSetter<F> where F: FnMut(&NodeId, AttributeId, DataValue) -> Result<(), StatusCode> + Send {
    fn set(&mut self, node_id: &NodeId, attribute_id: AttributeId, data_value: DataValue) -> Result<(), StatusCode> {
        (self.setter)(node_id, attribute_id, data_value)
    }
}

impl<F> AttrFnSetter<F> where F: FnMut(&NodeId, AttributeId, DataValue) -> Result<(), StatusCode> + Send {
    pub fn new(setter: F) -> AttrFnSetter<F> { AttrFnSetter { setter } }
}

/// This is a sanity saving macro that adds Node trait methods to all types that have a base
/// member.
macro_rules! node_impl {
    ( $node_struct:ident ) => {
        use opcua_types::*;
        use opcua_types::status_code::StatusCode;
        use opcua_types::service_types::NodeClass;
        use crate::address_space::node::NodeType;

        impl Into<NodeType> for $node_struct {
            fn into(self) -> NodeType { NodeType::$node_struct(self) }
        }

        impl Node for $node_struct {
            fn base(&self) -> &Base {
                &self.base
            }

            fn base_mut(&mut self) -> &mut Base {
                &mut self.base
            }

            fn node_class(&self) -> NodeClass {
                self.base().node_class()
            }

            fn node_id(&self) -> NodeId {
                self.base().node_id()
            }

            fn browse_name(&self) -> QualifiedName {
                self.base().browse_name()
            }

            fn display_name(&self) -> LocalizedText {
                self.base().display_name()
            }

            fn set_display_name(&mut self, display_name: LocalizedText) {
                self.base_mut().set_display_name(display_name);
            }

            fn description(&self) -> Option<LocalizedText> {
                self.base().description()
            }

            fn set_description(&mut self, description: LocalizedText) {
                self.base_mut().set_description(description);
            }

            fn write_mask(&self) -> Option<WriteMask> {
                self.base().write_mask()
            }

            fn set_write_mask(&mut self, write_mask: WriteMask) {
                self.base_mut().set_write_mask(write_mask);
            }

            fn user_write_mask(&self) -> Option<WriteMask> {
                self.base().user_write_mask()
            }

            fn set_user_write_mask(&mut self, user_write_mask: WriteMask) {
                self.base_mut().set_user_write_mask(user_write_mask)
            }
        }
    }
}

pub mod address_space;
pub mod base;
pub mod relative_path;
pub mod object;
pub mod variable;
pub mod method;
pub mod node;
pub mod reference_type;
pub mod object_type;
pub mod variable_type;
pub mod data_type;
pub mod view;
pub mod event_filter;
mod references;

#[cfg(feature = "generated-address-space")]
mod generated;
#[cfg(feature = "generated-address-space")]
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
    pub use super::base::Base;
    pub use super::{AttrFnGetter, AttrFnSetter};
    pub use super::address_space::AddressSpace;
    pub use super::references::ReferenceDirection;
    pub use super::data_type::DataType;
    pub use super::object::Object;
    pub use super::variable::{VariableBuilder, Variable};
    pub use super::method::Method;
    pub use super::reference_type::ReferenceType;
    pub use super::object_type::ObjectType;
    pub use super::variable_type::VariableType;
    pub use super::view::View;
    pub use super::node::{Node, NodeType};
}

pub use self::address_space::AddressSpace;
