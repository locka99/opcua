use opcua_core::types::*;
use opcua_core::services::*;

use address_space::*;

// This should match size of AttributeId
const NUM_ATTRIBUTES: usize = 22;

/// The NodeId is the target node. The reference is held in a list by the source node.
/// The target node does not need to exist.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub reference_type_id: ReferenceTypeId,
    pub node_id: NodeId,
}

impl Reference {
    pub fn new(reference_type_id: ReferenceTypeId, node_id: &NodeId) -> Reference {
        Reference {
            reference_type_id: reference_type_id,
            node_id: node_id.clone(),
        }
    }
}

/// Implemented by Base and all derived Node types. Functions that return a result in an Option
/// do so because the attribute is optional and not necessarily there.
pub trait Node {
    fn node_class(&self) -> NodeClass;
    fn node_id(&self) -> NodeId;
    fn browse_name(&self) -> QualifiedName;
    fn display_name(&self) -> LocalizedText;
    fn description(&self) -> Option<LocalizedText>;
    fn write_mask(&self) -> Option<UInt32>;
    fn user_write_mask(&self) -> Option<UInt32>;
    fn find_attribute(&self, attribute_id: AttributeId) -> Option<DataValue>;
}

/// This is a sanity saving macro that adds Node trait methods to all types that have a base
/// member.

macro_rules! node_impl {
    ( $node_struct:ty ) => {
        impl Node for $node_struct {
            fn node_class(&self) -> NodeClass { self.base.node_class() }
            fn node_id(&self) -> NodeId { self.base.node_id() }
            fn browse_name(&self) -> QualifiedName { self.base.browse_name() }
            fn display_name(&self) -> LocalizedText { self.base.display_name() }
            fn description(&self) -> Option<LocalizedText> { self.base.description() }
            fn write_mask(&self) -> Option<UInt32> { self.base.write_mask() }
            fn user_write_mask(&self) -> Option<UInt32> { self.base.user_write_mask() }
            fn find_attribute(&self, attribute_id: AttributeId) -> Option<Attribute> { self.base.find_attribute(attribute_id); }
        }
    };
}

#[macro_export]
macro_rules! find_attribute_mandatory {
    ( $sel:expr, $attr: ident ) => {
        let attribute_id = AttributeId::$attr;
        let attribute = $sel.find_attribute(&attribute_id);
        if attribute.is_some() {
            let attribute = attribute.unwrap();
            if let Attribute::$attr(value) = attribute.clone() {
                return value;
            }
        }
        panic!("Mandatory attribute {:?} is missing", attribute_id);
    }
}

/// Base is the functionality that all kinds of nodes need. Part 3, diagram B.4
#[derive(Debug, Clone, PartialEq)]
pub struct Base {
    /// Attributes
    pub attributes: Vec<Option<DataValue>>,
}

impl Node for Base {
    /// Returns the node class
    fn node_class(&self) -> NodeClass {
        let result = find_attribute_value_mandatory!(self, NodeClass, Int32);
        NodeClass::from_i32(result).unwrap()
    }

    fn node_id(&self) -> NodeId {
        find_attribute_value_mandatory!(self, NodeId, NodeId)
    }

    fn browse_name(&self) -> QualifiedName {
        find_attribute_value_mandatory!(self, BrowseName, QualifiedName)
    }

    fn display_name(&self) -> LocalizedText {
        find_attribute_value_mandatory!(self, DisplayName, LocalizedText)
    }

    fn description(&self) -> Option<LocalizedText> {
        find_attribute_value_optional!(self, Description, LocalizedText)
    }

    fn write_mask(&self) -> Option<UInt32> {
        find_attribute_value_optional!(self, WriteMask, UInt32)
    }

    fn user_write_mask(&self) -> Option<UInt32> {
        find_attribute_value_optional!(self, UserWriteMask, UInt32)
    }

    fn find_attribute(&self, attribute_id: AttributeId) -> Option<DataValue> {
        let attribute_idx = Base::attribute_idx(attribute_id);
        if attribute_idx >= self.attributes.len() {
            warn!("Attribute id {:?} is out of range and invalid", attribute_id);
            return None;
        }
        self.attributes[attribute_idx].clone()
    }
}

impl Base {
    pub fn new(node_class: NodeClass, node_id: &NodeId, browse_name: &str, display_name: &str, mut attributes: Vec<(AttributeId, Variant)>) -> Base {
        // Mandatory attributes
        let mut attributes_to_add = vec![
            (AttributeId::NodeClass, Variant::Int32(node_class as Int32)),
            (AttributeId::NodeId, Variant::NodeId(node_id.clone())),
            (AttributeId::DisplayName, Variant::LocalizedText(LocalizedText::new("", display_name))),
            (AttributeId::BrowseName, Variant::QualifiedName(QualifiedName::new(0, browse_name))),
            (AttributeId::Description, Variant::LocalizedText(LocalizedText::new("", ""))),
            (AttributeId::WriteMask, Variant::UInt32(0)),
            (AttributeId::UserWriteMask, Variant::UInt32(0)),
            (AttributeId::Description, Variant::LocalizedText(LocalizedText::new("", ""))),
        ];
        attributes_to_add.append(&mut attributes);

        let mut attributes: Vec<Option<DataValue>> = Vec::with_capacity(NUM_ATTRIBUTES);
        for _ in 0..NUM_ATTRIBUTES {
            attributes.push(None);
        }
        // Make attributes from their initial values
        let now = DateTime::now();
        for attribute in attributes_to_add {
            let (attribute_id, value) = attribute;
            let attribute_idx = Base::attribute_idx(attribute_id);
            attributes[attribute_idx] = Some(DataValue {
                value: Some(value),
                status: Some(GOOD),
                server_timestamp: Some(now.clone()),
                server_picoseconds: Some(0),
                source_timestamp: Some(now.clone()),
                source_picoseconds: Some(0),
            });
        }

        Base {
            attributes: attributes,
        }
    }

    pub fn set_attribute(&mut self, attribute_id: AttributeId, value: DataValue) {
        let attribute_idx = Base::attribute_idx(attribute_id);
        self.attributes[attribute_idx] = Some(value);
    }

    pub fn set_attribute_value(&mut self, attribute_id: AttributeId, value: Variant, server_timestamp: &DateTime, source_timestamp: &DateTime) {
        let attribute_idx = Base::attribute_idx(attribute_id);
        self.attributes[attribute_idx] = Some(DataValue {
            value: Some(value),
            status: Some(GOOD),
            server_timestamp: Some(server_timestamp.clone()),
            server_picoseconds: Some(0),
            source_timestamp: Some(source_timestamp.clone()),
            source_picoseconds: Some(0),
        });
    }

    pub fn update_attribute_value(&mut self, attribute_id: AttributeId, value: Variant, server_timestamp: &DateTime, source_timestamp: &DateTime) -> Result<(), ()> {
        let ref mut attribute = self.attributes[Base::attribute_idx(attribute_id)];
        if let &mut Some(ref mut attribute) = attribute {
            attribute.value = Some(value);
            attribute.server_timestamp = Some(server_timestamp.clone());
            attribute.source_timestamp = Some(source_timestamp.clone());
            Ok(())
        } else {
            Err(())
        }
    }

    #[inline]
    pub fn attribute_idx(attribute_id: AttributeId) -> usize {
        attribute_id as usize - 1
    }
}
