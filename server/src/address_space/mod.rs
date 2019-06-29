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

// A macro for creating builders. Builders can be used for more conveniently creating objects,
// variables etc.
macro_rules! node_builder_impl {
    ( $node_builder_ty:ident, $node_ty:ident ) => {
        use $crate::address_space::{
            address_space::AddressSpace,
            references::ReferenceDirection,
        };

        pub struct $node_builder_ty {
            node: $node_ty,
            references: Vec<(NodeId, ReferenceTypeId, ReferenceDirection)>,
        }

        impl $node_builder_ty {
            pub fn new<T, S>(node_id: &NodeId, browse_name: T, display_name: S) -> Self
                where T: Into<QualifiedName>,
                      S: Into<LocalizedText>,
            {
                Self {
                    node: $node_ty::default(),
                    references: Vec::with_capacity(10),
                }
                    .node_id(node_id.clone())
                    .browse_name(browse_name)
                    .display_name(display_name)
            }

            pub fn is_valid(&self) -> bool {
                self.node.is_valid()
            }

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

            pub fn reference<T>(mut self, node_id: T, reference_type_id: ReferenceTypeId, reference_direction: ReferenceDirection) -> Self
                where T: Into<NodeId>
            {
                self.references.push((node_id.into(), reference_type_id, reference_direction));
                self
            }

            pub fn organizes<T>(self, organizes_id: T) -> Self where T: Into<NodeId> {
                self.reference(organizes_id, ReferenceTypeId::Organizes, ReferenceDirection::Forward)
            }

            pub fn organized_by<T>(self, organized_by_id: T) -> Self where T: Into<NodeId> {
                self.reference(organized_by_id, ReferenceTypeId::Organizes, ReferenceDirection::Inverse)
            }

            /// Yields a built node. This function will panic if the node is invalid.
            pub fn build(self) -> $node_ty {
                if self.is_valid() {
                    self.node
                } else {
                    panic!("The node is not valid, node id = {:?}", self.node.base.node_id());
                }
            }

            // Inserts the node into the address space, including references
            pub fn insert(self, address_space: &mut AddressSpace) {
                if self.is_valid() {
                    if !self.references.is_empty() {
                        let references = self.references.iter().map(|v| {
                            (&v.0, v.1, v.2)
                        }).collect::<Vec<_>>();
                        address_space.insert(self.node, Some(references.as_slice()));
                    } else {
                        address_space.insert(self.node, None);
                    };
                } else {
                    panic!("The node is not valid, node id = {:?}", self.node.base.node_id());
                }
            }
        }
    }
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
pub mod references;

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

bitflags! {
    pub struct EventNotifier: u8 {
        const SUBSCRIBE_TO_EVENTS = 1;
        const HISTORY_READ = 4;
        const HISTORY_WRITE = 8;
    }
}

pub mod types {
    pub use super::base::Base;
    pub use super::{AttrFnGetter, AttrFnSetter};
    pub use super::address_space::AddressSpace;
    pub use super::references::ReferenceDirection;
    pub use super::data_type::DataType;
    pub use super::object::{ObjectBuilder, Object};
    pub use super::variable::{VariableBuilder, Variable};
    pub use super::method::Method;
    pub use super::reference_type::ReferenceType;
    pub use super::object_type::{ObjectTypeBuilder, ObjectType};
    pub use super::variable_type::VariableType;
    pub use super::view::View;
    pub use super::node::{Node, NodeType};
}

pub use self::address_space::AddressSpace;
