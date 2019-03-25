use opcua_types::service_types::ViewAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct View {
    base: Base,
}

node_impl!(View);

impl View {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, event_notifier: u8, contains_no_loops: bool) -> View
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
            (AttributeId::EventNotifier, Variant::Byte(event_notifier)),
            (AttributeId::ContainsNoLoops, Variant::Boolean(contains_no_loops)),
        ];
        View {
            base: Base::new(NodeClass::View, node_id, browse_name, display_name, attributes),
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: ViewAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mut node = Self::new(node_id, browse_name, "", 0u8, false);
        let mask = AttributesMask::from_bits_truncate(attributes.specified_attributes);
        if mask.contains(AttributesMask::DISPLAY_NAME) {
            node.set_display_name(attributes.display_name);
        }
        if mask.contains(AttributesMask::DESCRIPTION) {
            node.set_description(attributes.description);
        }
        if mask.contains(AttributesMask::WRITE_MASK) {
            node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
        }
        if mask.contains(AttributesMask::USER_WRITE_MASK) {
            node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
        }
        if mask.contains(AttributesMask::EVENT_NOTIFIER) {
            node.set_event_notifier(attributes.event_notifier);
        }
        if mask.contains(AttributesMask::CONTAINS_NO_LOOPS) {
            node.set_contains_no_loops(attributes.contains_no_loops);
        }
        Ok(node)
    }

    pub fn event_notifier(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, EventNotifier, Boolean)
    }

    pub fn set_event_notifier(&mut self, event_notifier: u8) {
        let _ = self.set_attribute(AttributeId::EventNotifier, Variant::Byte(event_notifier).into());
    }

    pub fn contains_no_loops(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, ContainsNoLoops, Boolean)
    }

    pub fn set_contains_no_loops(&mut self, contains_no_loops: bool) {
        let _ = self.set_attribute(AttributeId::ContainsNoLoops, Variant::Boolean(contains_no_loops).into());
    }
}
