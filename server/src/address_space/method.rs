use crate::address_space::base::Base;
use crate::address_space::node::Node;

#[derive(Debug)]
pub struct Method {
    base: Base,
}

node_impl!(Method);

impl Method {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, is_abstract: bool, executable: bool, user_executable: bool) -> Method {
        // Mandatory
        let attributes = vec![
            (AttributeId::IsAbstract, Variant::Boolean(is_abstract)),
            (AttributeId::Executable, Variant::Boolean(executable)),
            (AttributeId::UserExecutable, Variant::Boolean(user_executable)),
        ];

        // Optional attributes
        //
        // NodeVersion - String
        //
        // InputArguments - Argument[]
        // OutputArguments - Argument[]
        //
        // Properties may be defined for methods using HasProperty references.
        // The InputArguments and OutputArguments both contain an array
        // of the DataType argument as defined in 8.6. An empty array
        // or a property that is not provided indicates there are
        // no input arguments or output arguments for the method.

        Method {
            base: Base::new(NodeClass::Method, node_id, browse_name, display_name, description, attributes),
        }
    }

    pub fn is_abstract(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, IsAbstract, Boolean)
    }

    pub fn executable(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, Executable, Boolean)
    }

    pub fn user_executable(&self) -> bool {
        // User executable cannot be true unless executable is true
        if self.executable() {
            // TODO this should check the current session state to determine if the user
            // has permissions to execute this method
            find_attribute_value_mandatory!(&self.base, UserExecutable, Boolean)
        } else {
            false
        }
    }
}
