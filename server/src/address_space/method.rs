use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Method {
    base: Base,
}

node_impl!(Method);

impl Method {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, is_abstract: Boolean, executable: Boolean, user_executable: Boolean) -> Method {
        // Mandatory
        let attributes = vec![
            AttributeValue::IsAbstract(is_abstract),
            AttributeValue::Executable(executable),
            AttributeValue::UserExecutable(user_executable),
        ];
        let properties = vec![];
        Method {
            base: Base::new(NodeClass::Method, node_id, browse_name, display_name, attributes, properties),
        }
    }

    pub fn is_abstract(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, IsAbstract);
    }

    pub fn executable(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, Executable);
    }

    pub fn user_executable(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, UserExecutable);
    }
}
