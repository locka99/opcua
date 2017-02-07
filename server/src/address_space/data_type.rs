use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub struct DataType {
    base: Base,
}

node_impl!(DataType);

impl DataType {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str) -> DataType {
        let attributes = vec![];
        let properties = vec![];
        DataType {
            base: Base::new(NodeClass::DataType, node_id, browse_name, display_name, attributes, properties),
        }
    }
}
