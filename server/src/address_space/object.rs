use opcua_types::service_types::ObjectAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct Object {
    base: Base,
}

node_impl!(Object);

impl Object {
    pub fn new<R, S, T>(node_id: &NodeId, browse_name: R, display_name: S, description: T) -> Object
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              T: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
            (AttributeId::EventNotifier, Variant::Byte(0))
        ];
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn event_notifier(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, EventNotifier, Boolean)
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: ObjectAttributes) -> Self where S: Into<QualifiedName> {
        let mut node = Self::new(node_id, browse_name, "", "");
        let mask = AttributesMask::from_bits_truncate(attributes.specified_attributes);
        if mask.contains(AttributesMask::DISPLAY_NAME) {
            node.base.set_display_name(attributes.display_name);
        }
        if mask.contains(AttributesMask::DESCRIPTION) {
            node.base.set_description(attributes.description);
        }
        if mask.contains(AttributesMask::WRITE_MASK) {
            node.base.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
        }
        if mask.contains(AttributesMask::USER_WRITE_MASK) {
            node.base.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
        }
        if mask.contains(AttributesMask::EVENT_NOTIFIER) {
            let _ = node.set_attribute(AttributeId::EventNotifier, Variant::Byte(attributes.event_notifier).into());
        }
        node
    }
}