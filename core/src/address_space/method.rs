use address_space::*;
use types::*;
use services::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Method {
    base: Base,
}

node_impl!(Method);

impl Method {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, is_abstract: bool, executable: bool, user_executable: bool) -> Method {
        // Mandatory
        let attributes = vec![
            Attribute::IsAbstract(is_abstract),
            Attribute::Executable(executable),
            Attribute::UserExecutable(user_executable),
        ];
        let references = vec![];
        let properties = vec![];
        Method {
            base: Base::new(NodeClass::Method, node_id, browse_name, display_name, attributes, references, properties),
        }
    }
}
