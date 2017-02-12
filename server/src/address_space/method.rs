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
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
            (AttributeId::Executable, Variant::Boolean(executable)),
            (AttributeId::UserExecutable, Variant::Boolean(user_executable)),
        ];
        Method {
            base: Base::new(NodeClass::Method, node_id, browse_name, display_name, attributes),
        }
    }

    pub fn is_abstract(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn executable(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, Executable, Boolean)
    }

    pub fn user_executable(&self) -> Boolean {
        find_attribute_value_mandatory!(&self.base, UserExecutable, Boolean)
    }
}
