use crate::address_space::{base::Base, node::Node};
use opcua_types::service_types::MethodAttributes;

#[derive(Debug)]
pub struct Method {
    base: Base,
}

node_impl!(Method);

impl Method {
    pub fn new<R, S, T>(node_id: &NodeId, browse_name: R, display_name: S, description: T, executable: bool, user_executable: bool) -> Method
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
              T: Into<LocalizedText>,
    {
        // Mandatory
        let attributes = vec![
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

    pub fn from_attributes(node_id: &NodeId, browse_name: &QualifiedName, attributes: MethodAttributes) -> Self {
        let mut node = Self::new(node_id, browse_name.name.as_ref(), "", "", false, false);
        let mask = AttributesMask::from_bits_truncate(attributes.specified_attributes);
        if mask.contains(AttributesMask::DISPLAY_NAME) {
            node.base.set_display_name(attributes.display_name);
        }
        if mask.contains(AttributesMask::DESCRIPTION) {
            node.base.set_description(attributes.description);
        }
        if mask.contains(AttributesMask::WRITE_MASK) {
            node.base.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
        }
        if mask.contains(AttributesMask::USER_WRITE_MASK) {
            node.base.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
        }
        if mask.contains(AttributesMask::EXECUTABLE) {
            let _ = node.set_attribute(AttributeId::Executable, Variant::Boolean(attributes.executable).into());
        }
        if mask.contains(AttributesMask::USER_EXECUTABLE) {
            let _ = node.set_attribute(AttributeId::UserExecutable, Variant::Boolean(attributes.user_executable).into());
        }
        node
    }

    pub fn executable(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, Executable, Boolean)
    }

    pub fn user_executable(&self) -> bool {
        // User executable cannot be true unless executable is true
        if self.executable() {
            // TODO this should check the current session state to determine if the user
            //  has permissions to execute this method
            find_attribute_value_mandatory!(&self.base, UserExecutable, Boolean)
        } else {
            false
        }
    }
}
