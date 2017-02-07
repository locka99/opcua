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

#[derive(Debug, Clone, PartialEq)]
pub enum Property {
    NodeVersion(UAString),
    ViewVersion(UInt32),
    Icon,
    NamingRule,
    // TODO
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
    fn find_attribute(&self, attribute_id: AttributeId) -> Option<Attribute>;
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
    pub attributes: Vec<Option<Attribute>>,
    /// Properties
    pub properties: Vec<Property>,
}


impl Node for Base {
    /// Returns the node class
    fn node_class(&self) -> NodeClass {
        find_attribute_value_mandatory!(self, NodeClass);
    }

    fn node_id(&self) -> NodeId {
        find_attribute_value_mandatory!(self, NodeId);
    }

    fn browse_name(&self) -> QualifiedName {
        find_attribute_value_mandatory!(self, BrowseName);
    }

    fn display_name(&self) -> LocalizedText {
        find_attribute_value_mandatory!(self, DisplayName);
    }

    fn description(&self) -> Option<LocalizedText> {
        find_attribute_value_optional!(self, Description);
    }

    fn write_mask(&self) -> Option<UInt32> {
        find_attribute_value_optional!(self, WriteMask);
    }

    fn user_write_mask(&self) -> Option<UInt32> {
        find_attribute_value_optional!(self, UserWriteMask);
    }

    fn find_attribute(&self, attribute_id: AttributeId) -> Option<Attribute> {
        let attribute_idx = Base::attribute_idx(attribute_id);
        if attribute_idx >= self.attributes.len() {
            warn!("Attribute id {:?} is out of range and invalid", attribute_id);
            return None;
        }
        self.attributes[attribute_idx].clone()
    }
}

impl Base {
    pub fn new(node_class: NodeClass, node_id: &NodeId, browse_name: &str, display_name: &str, mut attributes: Vec<AttributeValue>, mut properties: Vec<Property>) -> Base {
        // Mandatory attributes
        let mut attributes_to_add = vec![
            AttributeValue::NodeClass(node_class),
            AttributeValue::NodeId(node_id.clone()),
            AttributeValue::DisplayName(LocalizedText::new("", display_name)),
            AttributeValue::BrowseName(QualifiedName::new(0, browse_name))
        ];
        attributes_to_add.append(&mut attributes);

        let mut attributes: Vec<Option<Attribute>> = Vec::with_capacity(NUM_ATTRIBUTES);
        for _ in 0..NUM_ATTRIBUTES {
            attributes.push(None);
        }
        // Make attributes from their initial values
        let now = DateTime::now();
        for attribute in attributes_to_add {
            let attribute_id = attribute.attribute_id();
            let attribute_idx = attribute.attribute_id() as usize - 1;
            attributes[attribute_idx] = Some(Attribute {
                id: attribute_id,
                value: attribute,
                server_timestamp: now.clone(),
                server_picoseconds: 0,
                source_timestamp: now.clone(),
                source_picoseconds: 0,
            });
        }

        let mut base_properties = vec![];
        base_properties.append(&mut properties);

        Base {
            attributes: attributes,
            properties: base_properties,
        }
    }

    pub fn set_attribute(&mut self, attribute_id: AttributeId, value: AttributeValue, server_timestamp: &DateTime, source_timestamp: &DateTime) {
        let attribute_idx = attribute_id as usize - 1;
        self.attributes[attribute_idx] = Some(Attribute {
            id: attribute_id,
            value: value,
            server_timestamp: server_timestamp.clone(),
            server_picoseconds: 0,
            source_timestamp: source_timestamp.clone(),
            source_picoseconds: 0,
        });
    }

    pub fn update_attribute_value(&mut self, attribute_id: AttributeId, value: AttributeValue, server_timestamp: &DateTime, source_timestamp: &DateTime) -> Result<(), ()> {
        let ref mut attribute = self.attributes[Base::attribute_idx(attribute_id)];
        if let &mut Some(ref mut attribute) = attribute {
            attribute.value = value;
            attribute.server_timestamp = server_timestamp.clone();
            attribute.source_timestamp = source_timestamp.clone();
            Ok(())
        } else {
            Err(())
        }
    }

    #[inline]
    fn attribute_idx(attribute_id: AttributeId) -> usize {
        attribute_id as usize - 1
    }
}
