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
        // Mandatory
        let attributes = vec![
            Attribute::EventNotifier(false)
        ];

        let references = vec![
            Reference::HasTypeDefinition(ObjectTypeId::FolderType.as_node_id()),
        ];

        let properties = vec![];
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name, attributes, references, properties),
        }
    }

    pub fn add_organizes(&mut self, node_id: &NodeId) {
        self.add_reference(Reference::Organizes(node_id.clone()));
    }

    pub fn add_child(&mut self, node_id: &NodeId) {
        self.add_reference(Reference::HasChild(node_id.clone()));
    }

    pub fn add_property(&mut self, node_id: &NodeId) {
        self.add_reference(Reference::HasProperty(node_id.clone()));
    }

    pub fn event_notifier(&self) -> bool {
        find_attribute_mandatory!(&self.base, EventNotifier);
    }
}