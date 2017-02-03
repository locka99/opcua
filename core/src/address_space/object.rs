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
            AttributeValue::EventNotifier(false)
        ];

        //        let references = vec![
        //           Reference::HasTypeDefinition(ObjectTypeId::FolderType.as_node_id()),
        //       ];

        let properties = vec![];
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name, attributes, properties),
        }
    }

    pub fn event_notifier(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, EventNotifier);
    }

}