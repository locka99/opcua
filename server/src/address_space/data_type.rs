use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub struct DataType {
    base: Base,
}

node_impl!(DataType);

impl DataType {
    pub fn new_node(node_id: &NodeId, browse_name: &str, display_name: &str, is_abstract: Boolean) -> NodeType {
        NodeType::DataType(DataType::new(node_id, browse_name, display_name, is_abstract))
    }

    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, is_abstract: Boolean) -> DataType {
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        let properties = vec![];
        DataType {
            base: Base::new(NodeClass::DataType, node_id, browse_name, display_name, attributes, properties),
        }
    }
}
