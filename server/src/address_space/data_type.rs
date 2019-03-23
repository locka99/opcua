use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct DataType {
    base: Base,
}

node_impl!(DataType);

impl DataType {
    pub fn new<R, S, T>(node_id: &NodeId, browse_name: R, display_name: S, description: T, is_abstract: bool) -> DataType
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              T: Into<LocalizedText>,
    {
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
        ];
        DataType {
            base: Base::new(NodeClass::DataType, node_id, browse_name, display_name, description, attributes),
        }
    }
}
