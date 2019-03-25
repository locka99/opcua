use opcua_types::{
    NodeId, QualifiedName, LocalizedText, AttributeId, DataValue, WriteMask, Variant,
    service_types::NodeClass,
    status_code::StatusCode,
};

use crate::{
    address_space::types::{Object, ObjectType, ReferenceType, Variable, VariableType, View, DataType, Method}
};

#[derive(Debug)]
pub enum NodeType {
    Object(Object),
    ObjectType(ObjectType),
    ReferenceType(ReferenceType),
    Variable(Variable),
    VariableType(VariableType),
    View(View),
    DataType(DataType),
    Method(Method),
}

pub trait HasNodeId {
    fn node_id(&self) -> NodeId;
}

impl HasNodeId for NodeType {
    fn node_id(&self) -> NodeId {
        self.as_node().node_id()
    }
}

impl NodeType {
    pub fn as_node(&self) -> &dyn Node {
        match *self {
            NodeType::Object(ref value) => value,
            NodeType::ObjectType(ref value) => value,
            NodeType::ReferenceType(ref value) => value,
            NodeType::Variable(ref value) => value,
            NodeType::VariableType(ref value) => value,
            NodeType::View(ref value) => value,
            NodeType::DataType(ref value) => value,
            NodeType::Method(ref value) => value,
        }
    }

    pub fn as_mut_node(&mut self) -> &mut dyn Node {
        match *self {
            NodeType::Object(ref mut value) => value,
            NodeType::ObjectType(ref mut value) => value,
            NodeType::ReferenceType(ref mut value) => value,
            NodeType::Variable(ref mut value) => value,
            NodeType::VariableType(ref mut value) => value,
            NodeType::View(ref mut value) => value,
            NodeType::DataType(ref mut value) => value,
            NodeType::Method(ref mut value) => value,
        }
    }
}

/// Implemented by Base and all derived Node types. Functions that return a result in an Option
/// do so because the attribute is optional and not necessarily there.
pub trait Node {
    fn node_class(&self) -> NodeClass {
        let result = find_attribute_value_mandatory!(self, NodeClass, Int32);
        NodeClass::from_i32(result).unwrap()
    }

    fn node_id(&self) -> NodeId {
        let result = find_attribute_value_mandatory!(self, NodeId, NodeId);
        result.as_ref().clone()
    }

    fn browse_name(&self) -> QualifiedName {
        let result = find_attribute_value_mandatory!(self, BrowseName, QualifiedName);
        result.as_ref().clone()
    }

    fn display_name(&self) -> LocalizedText {
        let result = find_attribute_value_mandatory!(self, DisplayName, LocalizedText);
        result.as_ref().clone()
    }

    fn set_display_name(&mut self, display_name: LocalizedText) {
        let _ = self.set_attribute(AttributeId::DisplayName, Variant::from(display_name).into());
    }

    fn description(&self) -> Option<LocalizedText> {
        let result = find_attribute_value_optional!(self, Description, LocalizedText);
        if result.is_none() {
            None
        } else {
            Some(result.unwrap().as_ref().clone())
        }
    }

    fn set_description(&mut self, description: LocalizedText) {
        let _ = self.set_attribute(AttributeId::Description, Variant::from(description).into());
    }

    fn write_mask(&self) -> Option<WriteMask> {
        find_attribute_value_optional!(self, WriteMask, UInt32).map(|write_mask| WriteMask::from_bits_truncate(write_mask))
    }

    fn set_write_mask(&mut self, write_mask: WriteMask) {
        let _ = self.set_attribute(AttributeId::WriteMask, DataValue::new(write_mask.bits()));
    }

    fn user_write_mask(&self) -> Option<WriteMask> {
        find_attribute_value_optional!(self, UserWriteMask, UInt32).map(|write_mask| WriteMask::from_bits_truncate(write_mask))
    }

    fn set_user_write_mask(&mut self, write_mask: WriteMask) {
        let _ = self.set_attribute(AttributeId::UserWriteMask, DataValue::new(write_mask.bits()));
    }

    /// Finds the attribute and value. The param `max_age` is a hint in milliseconds:
    ///
    /// * value 0, server shall attempt to read a new value from the data source
    /// * value >= i32::max(), sever shall attempt to get a cached value
    ///
    /// If there is a getter registered with the node, then the getter will interpret
    /// `max_age` how it sees fit.
    fn find_attribute(&self, attribute_id: AttributeId, max_age: f64) -> Option<DataValue>;

    /// Sets the attribute with the new value
    fn set_attribute(&mut self, attribute_id: AttributeId, value: DataValue) -> Result<(), StatusCode>;
}
