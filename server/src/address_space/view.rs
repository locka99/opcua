use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct View {
    base: Base,
}

node_impl!(View);

impl View {
    pub fn new<R, S, T>(node_id: &NodeId, browse_name: R, display_name: S, description: T, event_notifier: bool, contains_no_loops: bool) -> View
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              T: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
            (AttributeId::EventNotifier, Variant::Boolean(event_notifier)),
            (AttributeId::ContainsNoLoops, Variant::Boolean(contains_no_loops)),
        ];
        View {
            base: Base::new(NodeClass::View, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn event_notifier(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, EventNotifier, Boolean)
    }

    pub fn contains_no_loops(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, ContainsNoLoops, Boolean)
    }
}
