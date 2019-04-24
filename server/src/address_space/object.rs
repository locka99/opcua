use opcua_types::service_types::ObjectAttributes;

use crate::address_space::{base::Base, node::Node, node::NodeAttributes};

#[derive(Debug)]
pub struct Object {
    base: Base,
    event_notifier: u8,
}

node_impl!(Object);

impl NodeAttributes for Object {
    fn get_attribute(&self, attribute_id: AttributeId, max_age: f64) -> Option<DataValue> {
        self.base.get_attribute(attribute_id, max_age).or_else(|| {
            match attribute_id {
                AttributeId::EventNotifier => Some(Variant::from(self.event_notifier())),
                _ => None
            }.map(|v| v.into())
        })
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, value: Variant) -> Result<(), StatusCode> {
        if let Some(value) = self.base.set_attribute(attribute_id, value)? {
            match attribute_id {
                AttributeId::EventNotifier => {
                    if let Variant::Byte(v) = value {
                        self.set_event_notifier(v);
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

impl Object {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, event_notifier: u8) -> Object
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
        self.event_notifier
    }

    pub fn set_event_notifier(&mut self, event_notifier: u8) {
        self.event_notifier = event_notifier;
    }
}

