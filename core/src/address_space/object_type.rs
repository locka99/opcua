use address_space::*;
use types::*;
use services::*;

pub struct ObjectType {
    base: Base,
}

node_impl!(ObjectType);

impl ObjectType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, is_abstract: bool) -> ObjectType {
        // Mandatory
        let attributes = vec![
            Attribute::IsAbstract(is_abstract),
        ];
        let references = vec![];
        let properties = vec![];
        ObjectType {
            base: Base::new(NodeClass::ObjectType, node_id, browse_name, display_name, attributes, references, properties),
        }
    }
}