use opcua_types::service_types::MethodAttributes;

use crate::address_space::{base::Base, node::Node};

#[derive(Debug)]
pub struct Method {
    base: Base,
}

node_impl!(Method);

impl Method {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, executable: bool, user_executable: bool) -> Method
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
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
            base: Base::new(NodeClass::Method, node_id, browse_name, display_name, attributes),
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: MethodAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(AttributesMask::DISPLAY_NAME | AttributesMask::EXECUTABLE | AttributesMask::USER_EXECUTABLE) {
            let mut node = Self::new(node_id, browse_name, attributes.display_name, attributes.executable, attributes.user_executable);
            if mask.contains(AttributesMask::DESCRIPTION) {
                node.set_description(attributes.description);
            }
            if mask.contains(AttributesMask::WRITE_MASK) {
                node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
            }
            if mask.contains(AttributesMask::USER_WRITE_MASK) {
                node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
            }
            Ok(node)
        } else {
            error!("Method cannot be created from attributes - missing mandatory values");
            Err(())
        }
    }

    pub fn executable(&self) -> bool {
        find_attribute_value_mandatory!(&self.base, Executable, Boolean)
    }

    pub fn set_executable(&mut self, executable: bool) {
        let _ = self.set_attribute(AttributeId::Executable, Variant::Boolean(executable).into());
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

    pub fn set_user_executable(&mut self, user_executable: bool) {
        let _ = self.set_attribute(AttributeId::UserExecutable, Variant::Boolean(user_executable).into());
    }
}
