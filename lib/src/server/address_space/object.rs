// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Contains the implementation of `Object` and `ObjectBuilder`.

use crate::types::service_types::ObjectAttributes;

use super::{base::Base, node::Node, node::NodeBase, EventNotifier};

node_builder_impl!(ObjectBuilder, Object);
node_builder_impl_component_of!(ObjectBuilder);
node_builder_impl_property_of!(ObjectBuilder);

impl ObjectBuilder {
    pub fn is_folder(self) -> Self {
        self.has_type_definition(ObjectTypeId::FolderType)
    }

    pub fn event_notifier(mut self, event_notifier: EventNotifier) -> Self {
        self.node.set_event_notifier(event_notifier);
        self
    }

    pub fn has_type_definition<T>(self, type_id: T) -> Self
    where
        T: Into<NodeId>,
    {
        self.reference(
            type_id,
            ReferenceTypeId::HasTypeDefinition,
            ReferenceDirection::Forward,
        )
    }

    pub fn has_event_source<T>(self, source_id: T) -> Self
    where
        T: Into<NodeId>,
    {
        self.reference(
            source_id,
            ReferenceTypeId::HasEventSource,
            ReferenceDirection::Forward,
        )
    }
}

/// An `Object` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct Object {
    base: Base,
    event_notifier: EventNotifier,
}

impl Default for Object {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::Object, &NodeId::null(), "", ""),
            event_notifier: EventNotifier::empty(),
        }
    }
}

node_base_impl!(Object);

impl Node for Object {
    fn get_attribute_max_age(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: NumericRange,
        data_encoding: &QualifiedName,
        max_age: f64,
    ) -> Option<DataValue> {
        match attribute_id {
            AttributeId::EventNotifier => Some(self.event_notifier().bits().into()),
            _ => self.base.get_attribute_max_age(
                timestamps_to_return,
                attribute_id,
                index_range,
                data_encoding,
                max_age,
            ),
        }
    }

    fn set_attribute(
        &mut self,
        attribute_id: AttributeId,
        value: Variant,
    ) -> Result<(), StatusCode> {
        match attribute_id {
            AttributeId::EventNotifier => {
                if let Variant::Byte(v) = value {
                    self.set_event_notifier(EventNotifier::from_bits_truncate(v));
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => self.base.set_attribute(attribute_id, value),
        }
    }
}

impl Object {
    pub fn new<R, S>(
        node_id: &NodeId,
        browse_name: R,
        display_name: S,
        event_notifier: EventNotifier,
    ) -> Object
    where
        R: Into<QualifiedName>,
        S: Into<LocalizedText>,
    {
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name),
            event_notifier,
        }
    }

    pub fn from_attributes<S>(
        node_id: &NodeId,
        browse_name: S,
        attributes: ObjectAttributes,
    ) -> Result<Self, ()>
    where
        S: Into<QualifiedName>,
    {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::EVENT_NOTIFIER;

        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(mandatory_attributes) {
            let event_notifier = EventNotifier::from_bits_truncate(attributes.event_notifier);
            let mut node = Self::new(
                node_id,
                browse_name,
                attributes.display_name,
                event_notifier,
            );
            if mask.contains(AttributesMask::DESCRIPTION) {
                node.set_description(attributes.description);
            }
            if mask.contains(AttributesMask::WRITE_MASK) {
                node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
            }
            if mask.contains(AttributesMask::USER_WRITE_MASK) {
                node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
            }
            Ok(node)
        } else {
            error!("Object cannot be created from attributes - missing mandatory values");
            Err(())
        }
    }

    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    pub fn event_notifier(&self) -> EventNotifier {
        self.event_notifier
    }

    pub fn set_event_notifier(&mut self, event_notifier: EventNotifier) {
        self.event_notifier = event_notifier;
    }
}
