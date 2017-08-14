use address_space::{Base, Node, NodeType};

#[derive(Debug)]
pub struct ObjectType {
    base: Base,
}

node_impl!(ObjectType);

impl ObjectType {
    pub fn new_node(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, is_abstract: Boolean) -> NodeType {
        NodeType::ObjectType(ObjectType::new(node_id, browse_name, display_name, description, is_abstract))
    }

    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, is_abstract: Boolean) -> ObjectType {
        // Mandatory
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        ObjectType {
            base: Base::new(NodeClass::ObjectType, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn is_abstract(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }
}