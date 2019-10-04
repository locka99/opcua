//! Contains the implementation of `Method` and `MethodBuilder`.

use opcua_types::service_types::MethodAttributes;

use crate::address_space::{base::Base, node::NodeBase, node::Node};

node_builder_impl!(MethodBuilder, Method);
node_builder_impl_component_of!(MethodBuilder);
node_builder_impl_generates_event!(MethodBuilder);

/// A `Method` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct Method {
    base: Base,
    executable: bool,
    user_executable: bool,
}

impl Default for Method {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::Method, &NodeId::null(), "", ""),
            executable: false,
            user_executable: false,
        }
    }
}

node_base_impl!(Method);

impl Node for Method {
    fn get_attribute_max_age(&self, attribute_id: AttributeId, max_age: f64) -> Option<DataValue> {
        match attribute_id {
            AttributeId::Executable => Some(Variant::from(self.executable()).into()),
            AttributeId::UserExecutable => Some(Variant::from(self.user_executable()).into()),
            _ => self.base.get_attribute_max_age(attribute_id, max_age)
        }
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, value: Variant) -> Result<(), StatusCode> {
        match attribute_id {
            AttributeId::Executable => {
                if let Variant::Boolean(v) = value {
                    self.set_executable(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::UserExecutable => {
                if let Variant::Boolean(v) = value {
                    self.set_user_executable(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => self.base.set_attribute(attribute_id, value)
        }
    }
}

impl Method {
    pub fn new<R, S>(node_id: &NodeId, browse_name: R, display_name: S, executable: bool, user_executable: bool) -> Method
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
    {
        Method {
            base: Base::new(NodeClass::Method, node_id, browse_name, display_name),
            executable,
            user_executable,
        }
    }

    pub fn from_attributes<S>(node_id: &NodeId, browse_name: S, attributes: MethodAttributes) -> Result<Self, ()>
        where S: Into<QualifiedName>
    {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::EXECUTABLE | AttributesMask::USER_EXECUTABLE;
        let mask = AttributesMask::from_bits(attributes.specified_attributes).ok_or(())?;
        if mask.contains(mandatory_attributes) {
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

    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    pub fn executable(&self) -> bool {
        self.executable
    }

    pub fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }

    pub fn user_executable(&self) -> bool {
        // User executable cannot be true unless executable is true
        self.executable && self.user_executable
        // TODO this should check the current session state to determine if the user
        //  has permissions to execute this method
    }

    pub fn set_user_executable(&mut self, user_executable: bool) {
        self.user_executable = user_executable;
    }
}
