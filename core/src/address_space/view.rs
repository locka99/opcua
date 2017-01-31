use address_space::*;
use types::*;
use services::*;

#[derive(Debug, Clone, PartialEq)]
pub struct View {
    base: Base,
}

node_impl!(View);

// NodeClass::View

impl View {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, event_notifier: Boolean, contains_no_loops: Boolean) -> View {
        // Mandatory
        let attributes = vec![
            Attribute::EventNotifier(event_notifier),
            Attribute::ContainsNoLoops(contains_no_loops),
        ];
        let properties = vec![];
        View {
            base: Base::new(NodeClass::View, node_id, browse_name, display_name, attributes, properties),
        }
    }

    pub fn event_notifier(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, EventNotifier);
    }

    pub fn contains_no_loops(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, ContainsNoLoops);
    }
}
