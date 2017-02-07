use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub struct ObjectType {
    base: Base,
}

node_impl!(ObjectType);

impl ObjectType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, is_abstract: Boolean) -> ObjectType {
        // Mandatory
        let attributes = vec![
            AttributeValue::IsAbstract(is_abstract),
        ];
        let properties = vec![];
        ObjectType {
            base: Base::new(NodeClass::ObjectType, node_id, browse_name, display_name, attributes, properties),
        }
    }

    pub fn is_abstract(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, IsAbstract);
    }
}