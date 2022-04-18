// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides functionality to create an address space, find nodes, add nodes, change attributes
//! and values on nodes.

use std::{result::Result, sync::Arc};

use crate::sync::*;
use crate::types::status_code::StatusCode;
use crate::types::{
    AttributeId, DataValue, NodeId, NumericRange, QualifiedName, TimestampsToReturn,
};

use super::callbacks::{AttributeGetter, AttributeSetter};

pub use self::address_space::AddressSpace;

/// An implementation of attribute getter that can be easily constructed from a mutable function
pub struct AttrFnGetter<F>
where
    F: FnMut(
            &NodeId,
            TimestampsToReturn,
            AttributeId,
            NumericRange,
            &QualifiedName,
            f64,
        ) -> Result<Option<DataValue>, StatusCode>
        + Send,
{
    getter: F,
}

impl<F> AttributeGetter for AttrFnGetter<F>
where
    F: FnMut(
            &NodeId,
            TimestampsToReturn,
            AttributeId,
            NumericRange,
            &QualifiedName,
            f64,
        ) -> Result<Option<DataValue>, StatusCode>
        + Send,
{
    fn get(
        &mut self,
        node_id: &NodeId,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: NumericRange,
        data_encoding: &QualifiedName,
        max_age: f64,
    ) -> Result<Option<DataValue>, StatusCode> {
        (self.getter)(
            node_id,
            timestamps_to_return,
            attribute_id,
            index_range,
            data_encoding,
            max_age,
        )
    }
}

impl<F> AttrFnGetter<F>
where
    F: FnMut(
            &NodeId,
            TimestampsToReturn,
            AttributeId,
            NumericRange,
            &QualifiedName,
            f64,
        ) -> Result<Option<DataValue>, StatusCode>
        + Send,
{
    pub fn new(getter: F) -> AttrFnGetter<F> {
        AttrFnGetter { getter }
    }

    pub fn new_boxed(getter: F) -> Arc<Mutex<AttrFnGetter<F>>> {
        Arc::new(Mutex::new(Self::new(getter)))
    }
}

/// An implementation of attribute setter that can be easily constructed using a mutable function
pub struct AttrFnSetter<F>
where
    F: FnMut(&NodeId, AttributeId, NumericRange, DataValue) -> Result<(), StatusCode> + Send,
{
    setter: F,
}

impl<F> AttributeSetter for AttrFnSetter<F>
where
    F: FnMut(&NodeId, AttributeId, NumericRange, DataValue) -> Result<(), StatusCode> + Send,
{
    fn set(
        &mut self,
        node_id: &NodeId,
        attribute_id: AttributeId,
        index_range: NumericRange,
        data_value: DataValue,
    ) -> Result<(), StatusCode> {
        (self.setter)(node_id, attribute_id, index_range, data_value)
    }
}

impl<F> AttrFnSetter<F>
where
    F: FnMut(&NodeId, AttributeId, NumericRange, DataValue) -> Result<(), StatusCode> + Send,
{
    pub fn new(setter: F) -> AttrFnSetter<F> {
        AttrFnSetter { setter }
    }

    pub fn new_boxed(setter: F) -> Arc<Mutex<AttrFnSetter<F>>> {
        Arc::new(Mutex::new(Self::new(setter)))
    }
}

// A macro for creating builders. Builders can be used for more conveniently creating objects,
// variables etc.
macro_rules! node_builder_impl {
    ( $node_builder_ty:ident, $node_ty:ident ) => {
        use $crate::server::address_space::{
            address_space::AddressSpace, references::ReferenceDirection,
        };

        /// A builder for constructing a node of same name. This can be used as an easy way
        /// to create a node and the references it has to another node in a simple fashion.
        pub struct $node_builder_ty {
            node: $node_ty,
            references: Vec<(NodeId, NodeId, ReferenceDirection)>,
        }

        impl $node_builder_ty {
            /// Creates a builder for a node. All nodes are required to su
            pub fn new<T, S>(node_id: &NodeId, browse_name: T, display_name: S) -> Self
            where
                T: Into<QualifiedName>,
                S: Into<LocalizedText>,
            {
                trace!("Creating a node using a builder, node id {}", node_id);
                Self {
                    node: $node_ty::default(),
                    references: Vec::with_capacity(10),
                }
                .node_id(node_id.clone())
                .browse_name(browse_name)
                .display_name(display_name)
            }

            pub fn get_node_id(&self) -> NodeId {
                self.node.node_id()
            }

            fn node_id(mut self, node_id: NodeId) -> Self {
                let _ = self.node.base.set_node_id(node_id);
                self
            }

            fn browse_name<V>(mut self, browse_name: V) -> Self
            where
                V: Into<QualifiedName>,
            {
                let _ = self.node.base.set_browse_name(browse_name);
                self
            }

            fn display_name<V>(mut self, display_name: V) -> Self
            where
                V: Into<LocalizedText>,
            {
                self.node.set_display_name(display_name.into());
                self
            }

            /// Tests that the builder is in a valid state to build or insert the node.
            pub fn is_valid(&self) -> bool {
                self.node.is_valid()
            }

            /// Sets the description of the node
            pub fn description<V>(mut self, description: V) -> Self
            where
                V: Into<LocalizedText>,
            {
                self.node.set_description(description.into());
                self
            }

            /// Adds a reference to the node
            pub fn reference<T>(
                mut self,
                node_id: T,
                reference_type_id: ReferenceTypeId,
                reference_direction: ReferenceDirection,
            ) -> Self
            where
                T: Into<NodeId>,
            {
                self.references.push((
                    node_id.into(),
                    reference_type_id.into(),
                    reference_direction,
                ));
                self
            }

            /// Indicates this node organizes another node by its id.
            pub fn organizes<T>(self, organizes_id: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    organizes_id,
                    ReferenceTypeId::Organizes,
                    ReferenceDirection::Forward,
                )
            }

            /// Indicates this node is organised by another node by its id
            pub fn organized_by<T>(self, organized_by_id: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    organized_by_id,
                    ReferenceTypeId::Organizes,
                    ReferenceDirection::Inverse,
                )
            }

            /// Yields a built node. This function will panic if the node is invalid. Note that
            /// calling this function discards any references for the node, so there is no purpose
            /// in adding references if you intend to call this method.
            pub fn build(self) -> $node_ty {
                if self.is_valid() {
                    self.node
                } else {
                    panic!(
                        "The node is not valid, node id = {:?}",
                        self.node.base.node_id()
                    );
                }
            }

            /// Inserts the node into the address space, including references. This function
            /// will panic if the node is in an invalid state.
            pub fn insert(self, address_space: &mut AddressSpace) -> bool {
                if self.is_valid() {
                    if !self.references.is_empty() {
                        let references = self
                            .references
                            .iter()
                            .map(|v| (&v.0, &v.1, v.2))
                            .collect::<Vec<_>>();
                        address_space.insert(self.node, Some(references.as_slice()))
                    } else {
                        address_space.insert::<$node_ty, ReferenceTypeId>(self.node, None)
                    }
                } else {
                    panic!(
                        "The node is not valid, node id = {:?}",
                        self.node.base.node_id()
                    );
                }
            }
        }
    };
}

macro_rules! node_builder_impl_generates_event {
    ( $node_builder_ty:ident ) => {
        impl $node_builder_ty {
            pub fn generates_event<T>(self, event_type: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    event_type,
                    ReferenceTypeId::GeneratesEvent,
                    ReferenceDirection::Forward,
                )
            }
        }
    };
}

macro_rules! node_builder_impl_subtype {
    ( $node_builder_ty:ident ) => {
        impl $node_builder_ty {
            pub fn subtype_of<T>(self, type_id: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    type_id,
                    ReferenceTypeId::HasSubtype,
                    ReferenceDirection::Inverse,
                )
            }

            pub fn has_subtype<T>(self, subtype_id: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    subtype_id,
                    ReferenceTypeId::HasSubtype,
                    ReferenceDirection::Forward,
                )
            }
        }
    };
}

macro_rules! node_builder_impl_component_of {
    ( $node_builder_ty:ident ) => {
        impl $node_builder_ty {
            pub fn component_of<T>(self, component_of_id: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    component_of_id,
                    ReferenceTypeId::HasComponent,
                    ReferenceDirection::Inverse,
                )
            }

            pub fn has_component<T>(self, has_component_id: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    has_component_id,
                    ReferenceTypeId::HasComponent,
                    ReferenceDirection::Forward,
                )
            }
        }
    };
}

macro_rules! node_builder_impl_property_of {
    ( $node_builder_ty:ident ) => {
        impl $node_builder_ty {
            pub fn has_property<T>(self, has_component_id: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    has_component_id,
                    ReferenceTypeId::HasProperty,
                    ReferenceDirection::Forward,
                )
            }

            pub fn property_of<T>(self, component_of_id: T) -> Self
            where
                T: Into<NodeId>,
            {
                self.reference(
                    component_of_id,
                    ReferenceTypeId::HasProperty,
                    ReferenceDirection::Inverse,
                )
            }
        }
    };
}

/// This is a sanity saving macro that implements the NodeBase trait for nodes. It assumes the
/// node has a base: Base
macro_rules! node_base_impl {
    ( $node_struct:ident ) => {
        use crate::{
            server::address_space::node::NodeType,
            types::{status_code::StatusCode, *},
        };

        impl Into<NodeType> for $node_struct {
            fn into(self) -> NodeType {
                NodeType::$node_struct(Box::new(self))
            }
        }

        impl NodeBase for $node_struct {
            fn node_class(&self) -> NodeClass {
                self.base.node_class()
            }

            fn node_id(&self) -> NodeId {
                self.base.node_id()
            }

            fn browse_name(&self) -> QualifiedName {
                self.base.browse_name()
            }

            fn display_name(&self) -> LocalizedText {
                self.base.display_name()
            }

            fn set_display_name(&mut self, display_name: LocalizedText) {
                self.base.set_display_name(display_name);
            }

            fn description(&self) -> Option<LocalizedText> {
                self.base.description()
            }

            fn set_description(&mut self, description: LocalizedText) {
                self.base.set_description(description);
            }

            fn write_mask(&self) -> Option<WriteMask> {
                self.base.write_mask()
            }

            fn set_write_mask(&mut self, write_mask: WriteMask) {
                self.base.set_write_mask(write_mask);
            }

            fn user_write_mask(&self) -> Option<WriteMask> {
                self.base.user_write_mask()
            }

            fn set_user_write_mask(&mut self, user_write_mask: WriteMask) {
                self.base.set_user_write_mask(user_write_mask)
            }
        }
    };
}

pub mod address_space;
pub mod base;
pub mod data_type;
pub mod method;
pub mod node;
pub mod object;
pub mod object_type;
pub mod reference_type;
pub mod references;
pub mod relative_path;
pub mod variable;
pub mod variable_type;
pub mod view;

#[rustfmt::skip]
#[cfg(feature = "generated-address-space")]
mod generated;
#[cfg(feature = "generated-address-space")]
mod method_impls;

bitflags! {
    pub struct AccessLevel: u8 {
        const CURRENT_READ = 1;
        const CURRENT_WRITE = 2;
        const HISTORY_READ = 4;
        const HISTORY_WRITE = 8;
        // These can be uncommented if they become used
        // const SEMANTIC_CHANGE = 16;
        // const STATUS_WRITE = 32;
        // const TIMESTAMP_WRITE = 64;
    }
}

bitflags! {
    pub struct UserAccessLevel: u8 {
        const CURRENT_READ = 1;
        const CURRENT_WRITE = 2;
        const HISTORY_READ = 4;
        const HISTORY_WRITE = 8;
        // These can be uncommented if they become used
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
    pub use super::address_space::AddressSpace;
    pub use super::data_type::{DataType, DataTypeBuilder};
    pub use super::method::{Method, MethodBuilder};
    pub use super::node::{NodeBase, NodeType};
    pub use super::object::{Object, ObjectBuilder};
    pub use super::object_type::{ObjectType, ObjectTypeBuilder};
    pub use super::reference_type::{ReferenceType, ReferenceTypeBuilder};
    pub use super::references::ReferenceDirection;
    pub use super::variable::{Variable, VariableBuilder};
    pub use super::variable_type::{VariableType, VariableTypeBuilder};
    pub use super::view::{View, ViewBuilder};
    pub use super::{AttrFnGetter, AttrFnSetter};
}
