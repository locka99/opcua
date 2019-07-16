//! Contains the implementation of `Object` and `ObjectBuilder`.

use opcua_types::service_types::ObjectAttributes;

use crate::address_space::{
    EventNotifier,
    base::Base, node::Node, node::NodeAttributes,
};

node_builder_impl!(ObjectBuilder, Object);

impl ObjectBuilder {
    pub fn is_folder(self) -> Self {
        self.has_type_definition(ObjectTypeId::FolderType)
    }

    pub fn event_notifier(mut self, event_notifier: EventNotifier) -> Self {
        self.node.set_event_notifier(event_notifier);
        self
    }

    pub fn component_of<T>(self, component_of_id: T) -> Self where T: Into<NodeId> {
        self.reference(component_of_id, ReferenceTypeId::HasComponent, ReferenceDirection::Inverse)
    }

    pub fn has_component<T>(self, has_component_id: T) -> Self where T: Into<NodeId> {
        self.reference(has_component_id, ReferenceTypeId::HasComponent, ReferenceDirection::Forward)
    }

    pub fn property_of<T>(self, property_of_id: T) -> Self where T: Into<NodeId> {
        self.reference(property_of_id, ReferenceTypeId::HasProperty, ReferenceDirection::Inverse)
    }

    pub fn has_property<T>(self, has_property_id: T) -> Self where T: Into<NodeId> {
        self.reference(has_property_id, ReferenceTypeId::HasProperty, ReferenceDirection::Forward)
    }

    pub fn has_type_definition<T>(self, type_id: T) -> Self where T: Into<NodeId> {
        self.reference(type_id, ReferenceTypeId::HasTypeDefinition, ReferenceDirection::Forward)
    }
}

/// An `Object` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct Object {
    base: Base,
    event_notifier: EventNotifier,
}

node_impl!(Object);

impl NodeAttributes for Object {
    fn get_attribute(&self, attribute_id: AttributeId, max_age: f64) -> Option<DataValue> {
        self.base.get_attribute(attribute_id, max_age).or_else(|| {
            match attribute_id {
                AttributeId::EventNotifier => Some(Variant::from(self.event_notifier().bits())),
                _ => None
            }.map(|v| v.into())
        })
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, value: Variant) -> Result<(), StatusCode> {
        if let Some(value) = self.base.set_attribute(attribute_id, value)? {
            match attribute_id {
                AttributeId::EventNotifier => {
                    if let Variant::Byte(v) = value {
                        self.set_event_notifier(EventNotifier::from_bits_truncate(v));
                        Ok(())
                    } else {
                        Err(StatusCode::BadTypeMismatch)
                    }
                }
                _ => Err(StatusCode::BadAttributeIdInvalid)
            }
        } else {
            Ok(())
        }
    }
}

impl Default for Object {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::Object, &NodeId::null(), "", ""),
            event_notifier: EventNotifier::empty(),
        }
    }
}

impl Object {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, event_notifier: EventNotifier) -> Object
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
    {
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name),
            event_notifier,
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: ObjectAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::EVENT_NOTIFIER;

        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(mandatory_attributes) {
            let event_notifier = EventNotifier::from_bits_truncate(attributes.event_notifier);
            let mut node = Self::new(node_id, browse_name, attributes.display_name, event_notifier);
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

