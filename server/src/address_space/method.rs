use address_space::base::Base;
use address_space::node::{Node, NodeType};

#[derive(Debug)]
pub struct Method {
    base: Base,
}

node_impl!(Method);

impl Method {
    pub fn new_node(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, is_abstract: Boolean, executable: Boolean, user_executable: Boolean) -> NodeType {
        NodeType::Method(Method::new(node_id, browse_name, display_name, description, is_abstract, executable, user_executable))
    }

    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, is_abstract: Boolean, executable: Boolean, user_executable: Boolean) -> Method {
        // Mandatory
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
            (AttributeId::Executable, Variant::Boolean(executable)),
            (AttributeId::UserExecutable, Variant::Boolean(user_executable)),
        ];
        Method {
            base: Base::new(NodeClass::Method, node_id, browse_name, display_name, description, attributes),
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
