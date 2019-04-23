use opcua_types::{
    *,
    status_code::StatusCode,
    service_types::*,
};

/// Base node class contains the attributes that all other kinds of nodes need. Part 3, diagram B.4
#[derive(Debug)]
pub struct Base {
    /// The node id of this node
    node_id: NodeId,
    /// The node class of this node
    node_class: NodeClass,
    /// The node's browse name which must be unique amongst its siblings
    browse_name: QualifiedName,
    /// The human readable display name
    display_name: LocalizedText,
    /// The description of the node (optional)
    description: Option<LocalizedText>,
    /// Write mask bits (optional)
    write_mask: Option<u32>,
    /// User write mask bits (optional)
    user_write_mask: Option<u32>,
}

impl Base {
    pub fn new<R, S>(node_class: NodeClass, node_id: &NodeId, browse_name: R, display_name: S) -> Base
        where R: Into<QualifiedName>,
              S: Into<LocalizedText>,
    {
        Base {
            node_id: node_id.clone(),
            node_class,
            browse_name: browse_name.into(),
            display_name: display_name.into(),
            description: None,
            write_mask: None,
            user_write_mask: None,
        }
    }

    pub fn get_attribute(&self, attribute_id: AttributeId, _max_age: f64) -> Option<DataValue> {
        match attribute_id {
            AttributeId::NodeClass => {
                Some(DataValue::new(self.node_class as i32))
            }
            AttributeId::NodeId => {
                Some(DataValue::new(self.node_id.clone()))
            }
            AttributeId::BrowseName => {
                Some(DataValue::new(self.browse_name.clone()))
            }
            AttributeId::DisplayName => {
                Some(DataValue::new(self.display_name.clone()))
            }
            AttributeId::Description => {
                if self.description.is_some() {
                    Some(DataValue::new(self.description.as_ref().unwrap().clone()))
                } else {
                    None
                }
            }
            AttributeId::WriteMask => {
                if let Some(v) = self.write_mask {
                    Some(DataValue::from(Variant::from(v)))
                } else {
                    None
                }
            }
            AttributeId::UserWriteMask => {
                if let Some(v) = self.user_write_mask {
                    Some(DataValue::from(Variant::from(v)))
                } else {
                    None
                }
            }
            _ => {
                None
            }
        }
    }

    /// Tries to set the attribute if its one of the common attribute, otherwise it returns the value
    /// for the subclass to handle.
    pub fn set_attribute(&mut self, attribute_id: AttributeId, value: Variant) -> Result<Option<Variant>, StatusCode> {
        match attribute_id {
            AttributeId::NodeClass => {
                if let Variant::Int32(v) = value {
                    self.node_class = match v {
                        1 => NodeClass::Object,
                        2 => NodeClass::Variable,
                        4 => NodeClass::Method,
                        8 => NodeClass::ObjectType,
                        16 => NodeClass::VariableType,
                        32 => NodeClass::ReferenceType,
                        64 => NodeClass::DataType,
                        128 => NodeClass::View,
                        _ => { return Ok(None); }
                    };
                    Ok(None)
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::NodeId => {
                if let Variant::NodeId(v) = value {
                    self.node_id = *v;
                    Ok(None)
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::BrowseName => {
                if let Variant::QualifiedName(v) = value {
                    self.browse_name = *v;
                    Ok(None)
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::DisplayName => {
                if let Variant::LocalizedText(v) = value {
                    self.display_name = *v;
                    Ok(None)
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::Description => {
                if let Variant::LocalizedText(v) = value {
                    self.description = Some(*v);
                    Ok(None)
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::WriteMask => {
                if let Variant::UInt32(v) = value {
                    self.write_mask = Some(v);
                    Ok(None)
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::UserWriteMask => {
                if let Variant::UInt32(v) = value {
                    self.user_write_mask = Some(v);
                    Ok(None)
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => {
                // The value is sent back to the caller for further processing.
                Ok(Some(value))
            }
        }
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    pub fn node_class(&self) -> NodeClass {
        self.node_class
    }

    pub fn set_node_id(&mut self, node_id: NodeId) {
        self.node_id = node_id;
    }

    pub fn display_name(&self) -> LocalizedText {
        self.display_name.clone()
    }

    pub fn set_display_name<S>(&mut self, display_name: S) where S: Into<LocalizedText> {
        self.display_name = display_name.into();
    }

    pub fn browse_name(&self) -> QualifiedName {
        self.browse_name.clone()
    }

    pub fn set_browse_name<S>(&mut self, browse_name: S) where S: Into<QualifiedName> {
        self.browse_name = browse_name.into();
    }

    pub fn description(&self) -> Option<LocalizedText> {
        self.description.clone()
    }

    pub fn set_description<S>(&mut self, description: S) where S: Into<LocalizedText> {
        self.description = Some(description.into())
    }

    pub fn write_mask(&self) -> Option<WriteMask> {
        if let Some(write_mask) = self.write_mask {
            Some(WriteMask::from_bits_truncate(write_mask))
        } else {
            None
        }
    }

    pub fn set_write_mask(&mut self, write_mask: WriteMask) {
        self.write_mask = Some(write_mask.bits());
    }

    pub fn user_write_mask(&self) -> Option<WriteMask> {
        if let Some(user_write_mask) = self.user_write_mask {
            Some(WriteMask::from_bits_truncate(user_write_mask))
        } else {
            None
        }
    }

    pub fn set_user_write_mask(&mut self, user_write_mask: WriteMask) {
        self.user_write_mask = Some(user_write_mask.bits());
    }
}
