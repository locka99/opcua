use opcua_types::service_types::ObjectAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct Object {
    base: Base,
}

node_impl!(Object);

impl Object {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, event_notifier: u8) -> Object
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
            (AttributeId::EventNotifier, Variant::Byte(event_notifier))
        ];
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name, attributes),
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: ObjectAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::EVENT_NOTIFIER;

        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(mandatory_attributes) {
            let mut node = Self::new(node_id, browse_name, attributes.display_name, attributes.event_notifier);
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

    pub fn event_notifier(&self) -> u8 {
        find_attribute_value_mandatory!(&self.base, EventNotifier, Byte)
    }

    pub fn set_event_notifier(&mut self, event_notifier: u8) {
        let _ = self.set_attribute(AttributeId::EventNotifier, Variant::Byte(event_notifier).into());
    }
}

