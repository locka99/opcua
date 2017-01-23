use services::*;
use types::*;
use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Object {
    base: Base,
}

node_impl!(Object);

impl Object {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str) -> Object {
        let attrs = vec![
            Attribute::EventNotifier(false)
        ];
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name, attrs),
        }
    }

    pub fn event_notifier(&self) -> bool {
        find_attribute_mandatory!(&self.base, EventNotifier);
    }
}