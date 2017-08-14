use std;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};

use opcua_types::*;

use address_space::{AttributeGetter, AttributeSetter, Node};

// This should match size of AttributeId
const NUM_ATTRIBUTES: usize = 22;

/// The NodeId is the target node. The reference is held in a list by the source node.
/// The target node does not need to exist.
#[derive(Debug, Clone)]
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

/// This is a sanity saving macro that adds Node trait methods to all types that have a base
/// member.

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
pub struct Base {
    /// Attributes
    attributes: Vec<Option<DataValue>>,
    /// Attribute getters - if None, handled by Base
    attribute_getters: HashMap<AttributeId, Arc<Mutex<AttributeGetter + Send>>>,
    /// Attribute setters - if None, handled by Base
    attribute_setters: HashMap<AttributeId, Arc<Mutex<AttributeSetter + Send>>>,
}

impl Debug for Base {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "Base {{ base: {:?} }}", self.attributes)
    }
}

impl Node for Base {
    /// Returns the node class
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

    fn description(&self) -> Option<LocalizedText> {
        let result = find_attribute_value_optional!(self, Description, LocalizedText);
        if result.is_none() {
            None
        } else {
            Some(result.unwrap().as_ref().clone())
        }
    }

    fn write_mask(&self) -> Option<UInt32> {
        find_attribute_value_optional!(self, WriteMask, UInt32)
    }

    fn user_write_mask(&self) -> Option<UInt32> {
        find_attribute_value_optional!(self, UserWriteMask, UInt32)
    }

    fn find_attribute(&self, attribute_id: AttributeId) -> Option<DataValue> {
        if let Some(getter) = self.attribute_getters.get(&attribute_id) {
            let getter = getter.lock().unwrap();
            getter.get(attribute_id, self.node_id())
        }
        else {
            let attribute_idx = Base::attribute_idx(attribute_id);
            if attribute_idx >= self.attributes.len() {
                warn!("Attribute id {:?} is out of range and invalid", attribute_id);
                return None;
            }
            self.attributes[attribute_idx].clone()
        }
    }
}

impl Base {
    pub fn new(node_class: NodeClass, node_id: &NodeId, browse_name: &str, display_name: &str, description: &str, mut attributes: Vec<(AttributeId, Variant)>) -> Base {
        // Mandatory attributes
        let mut attributes_to_add = vec![
            (AttributeId::NodeClass, Variant::Int32(node_class as Int32)),
            (AttributeId::NodeId, Variant::new_node_id(node_id.clone())),
            (AttributeId::DisplayName, Variant::new_localized_text(LocalizedText::new("", display_name))),
            (AttributeId::BrowseName, Variant::new_qualified_name(QualifiedName::new(0, browse_name))),
            (AttributeId::Description, Variant::new_localized_text(LocalizedText::new("", description))),
            (AttributeId::WriteMask, Variant::UInt32(0)),
            (AttributeId::UserWriteMask, Variant::UInt32(0)),
        ];
        attributes_to_add.append(&mut attributes);

        // Make attributes from their initial values
        let now = DateTime::now();
        let mut attributes = vec![None; NUM_ATTRIBUTES];
        for (attribute_id, value) in attributes_to_add {
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
            attributes,
            attribute_getters: HashMap::new(),
            attribute_setters: HashMap::new(),
        }
    }


    pub fn set_attribute_getter(&mut self, attribute_id: AttributeId, getter: Arc<Mutex<AttributeGetter + Send>>) {
        self.attribute_getters.insert(attribute_id, getter);
    }

    pub fn set_attribute_setter(&mut self, attribute_id: AttributeId, setter: Arc<Mutex<AttributeSetter + Send>>) {
        self.attribute_setters.insert(attribute_id, setter);
    }

    pub fn set_attribute(&mut self, attribute_id: AttributeId, value: DataValue) {
        let attribute_idx = Base::attribute_idx(attribute_id);
        if let Some(setter) = self.attribute_setters.get(&attribute_id) {
            let mut setter = setter.lock().unwrap();
            setter.set(attribute_id, self.node_id(), value);
        }
        else {
            self.attributes[attribute_idx] = Some(value);
        }
    }

    pub fn set_attribute_value(&mut self, attribute_id: AttributeId, value: Variant, server_timestamp: &DateTime, source_timestamp: &DateTime) {
        self.set_attribute(attribute_id, DataValue {
            value: Some(value),
            status: Some(GOOD),
            server_timestamp: Some(server_timestamp.clone()),
            server_picoseconds: Some(0),
            source_timestamp: Some(source_timestamp.clone()),
            source_picoseconds: Some(0),
        });
    }

    #[inline]
    pub fn attribute_idx(attribute_id: AttributeId) -> usize {
        attribute_id as usize - 1
    }
}
