use address_space::base::Base;
use address_space::node::Node;

#[derive(Debug)]
pub struct DataType {
    base: Base,
}

node_impl!(DataType);

impl DataType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, is_abstract: Boolean) -> DataType {
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        DataType {
            base: Base::new(NodeClass::DataType, node_id, browse_name, display_name, description, attributes),
        }
    }
}
