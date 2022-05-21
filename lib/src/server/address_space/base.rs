// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::types::{status_code::StatusCode, *};

use super::node::{Node, NodeBase};

/// Base node class contains the attributes that all other kinds of nodes need. Part 3, diagram B.4
#[derive(Debug)]
pub(crate) struct Base {
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

impl NodeBase for Base {
    fn node_class(&self) -> NodeClass {
        self.node_class
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn browse_name(&self) -> QualifiedName {
        self.browse_name.clone()
    }

    fn display_name(&self) -> LocalizedText {
        self.display_name.clone()
    }

    fn set_display_name(&mut self, display_name: LocalizedText) {
        self.display_name = display_name;
    }

    fn description(&self) -> Option<LocalizedText> {
        self.description.clone()
    }

    fn set_description(&mut self, description: LocalizedText) {
        self.description = Some(description)
    }

    fn write_mask(&self) -> Option<WriteMask> {
        self.write_mask.map(WriteMask::from_bits_truncate)
    }

    fn set_write_mask(&mut self, write_mask: WriteMask) {
        self.write_mask = Some(write_mask.bits());
    }

    fn user_write_mask(&self) -> Option<WriteMask> {
        self.user_write_mask.map(WriteMask::from_bits_truncate)
    }

    fn set_user_write_mask(&mut self, user_write_mask: WriteMask) {
        self.user_write_mask = Some(user_write_mask.bits());
    }
}

impl Node for Base {
    fn get_attribute_max_age(
        &self,
        _timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        _index_range: NumericRange,
        _data_encoding: &QualifiedName,
        _max_age: f64,
    ) -> Option<DataValue> {
        match attribute_id {
            AttributeId::NodeClass => Some((self.node_class as i32).into()),
            AttributeId::NodeId => Some(self.node_id().into()),
            AttributeId::BrowseName => Some(self.browse_name().into()),
            AttributeId::DisplayName => Some(self.display_name().into()),
            AttributeId::Description => self.description().map(|description| description.into()),
            AttributeId::WriteMask => self.write_mask.map(|v| v.into()),
            AttributeId::UserWriteMask => self.user_write_mask.map(|v| v.into()),
            _ => None,
        }
    }

    /// Tries to set the attribute if its one of the common attribute, otherwise it returns the value
    /// for the subclass to handle.
    fn set_attribute(
        &mut self,
        attribute_id: AttributeId,
        value: Variant,
    ) -> Result<(), StatusCode> {
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
                        _ => {
                            return Ok(());
                        }
                    };
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::NodeId => {
                if let Variant::NodeId(v) = value {
                    self.node_id = *v;
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::BrowseName => {
                if let Variant::QualifiedName(v) = value {
                    self.browse_name = *v;
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::DisplayName => {
                if let Variant::LocalizedText(v) = value {
                    self.display_name = *v;
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::Description => {
                if let Variant::LocalizedText(v) = value {
                    self.description = Some(*v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::WriteMask => {
                if let Variant::UInt32(v) = value {
                    self.write_mask = Some(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::UserWriteMask => {
                if let Variant::UInt32(v) = value {
                    self.user_write_mask = Some(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => Err(StatusCode::BadAttributeIdInvalid),
        }
    }
}

impl Base {
    pub fn new<R, S>(
        node_class: NodeClass,
        node_id: &NodeId,
        browse_name: R,
        display_name: S,
    ) -> Base
    where
        R: Into<QualifiedName>,
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

    pub fn is_valid(&self) -> bool {
        let invalid = self.node_id().is_null() || self.browse_name.is_null();
        !invalid
    }

    pub fn set_node_id(&mut self, node_id: NodeId) {
        self.node_id = node_id;
    }

    pub fn set_browse_name<S>(&mut self, browse_name: S)
    where
        S: Into<QualifiedName>,
    {
        self.browse_name = browse_name.into();
    }
}
