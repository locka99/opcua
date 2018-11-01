use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct ObjectType {
    base: Base,
}

node_impl!(ObjectType);

impl ObjectType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, is_abstract: bool) -> ObjectType {
        // Mandatory
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        ObjectType {
            base: Base::new(NodeClass::ObjectType, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }
}