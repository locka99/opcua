use address_space::*;
use types::*;
use services::*;

pub struct View {
    base: Base,
}

node_impl!(View);

// NodeClass::View

impl View {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, event_notifier: bool, contains_no_loops: bool) -> View {
        // Mandatory
        let attributes = vec![
            Attribute::EventNotifier(event_notifier),
            Attribute::ContainsNoLoops(contains_no_loops),
        ];
        let references = vec![];
        let properties = vec![];
        View {
            base: Base::new(NodeClass::View, node_id, browse_name, display_name, attributes, references, properties),
        }
    }
}
