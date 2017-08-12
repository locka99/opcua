use address_space::{Base, Node, NodeType};

#[derive(Debug)]
pub struct Object {
    base: Base,
}

node_impl!(Object);

impl Object {
    pub fn new_node(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str) -> NodeType {
        NodeType::Object(Object::new(node_id, browse_name, display_name, description))
    }

    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str) -> Object {
        // Mandatory
        let attributes = vec![
            (AttributeId::EventNotifier, Variant::Byte(0))
        ];
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn event_notifier(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, EventNotifier, Boolean)
    }
}