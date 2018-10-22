use address_space::base::Base;
use address_space::node::Node;

#[derive(Debug)]
pub struct View {
    base: Base,
}

node_impl!(View);

impl View {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, event_notifier: bool, contains_no_loops: bool) -> View {
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
