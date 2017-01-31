use types::*;
use services::*;

// Attributes as defined in Part 4, Figure B.7

// Attributes sometimes required and sometimes optional

// Write mask bits

/// Indicates if the AccessLevel Attribute is writable.
pub const WRITE_MASK_ACCESS_LEVEL: UInt32 = 1 << 0;
/// Indicates if the ArrayDimensions Attribute is writable.
pub const WRITE_MASK_ARRAY_DIMENSTIONS: UInt32 = 1 << 1;
///Indicates if the BrowseName Attribute is writable.
pub const WRITE_MASK_BROWSE_NAME: UInt32 = 1 << 2;
/// Indicates if the ContainsNoLoops Attribute is writable.
pub const WRITE_MASK_CONTAINS_NO_LOOPS: UInt32 = 1 << 3;
/// Indicates if the DataType Attribute is writable.
pub const WRITE_MASK_DATA_TYPE: UInt32 = 1 << 4;
/// Indicates if the Description Attribute is writable.
pub const WRITE_MASK_DESCRIPTION: UInt32 = 1 << 5;
/// Indicates if the DisplayName Attribute is writable.
pub const WRITE_MASK_DISPLAY_NAME: UInt32 = 1 << 6;
/// Indicates if the EventNotifier Attribute is writable.
pub const WRITE_MASK_EVENT_NOTIFIER: UInt32 = 1 << 7;
/// Indicates if the Executable Attribute is writable.
pub const WRITE_MASK_EXECUTABLE: UInt32 = 1 << 8;
/// Indicates if the Historizing Attribute is writable.
pub const WRITE_MASK_HISTORIZING: UInt32 = 1 << 9;
/// Indicates if the InverseName Attribute is writable.
pub const WRITE_MASK_INVERSE_NAME: UInt32 = 1 << 10;
/// Indicates if the IsAbstract Attribute is writable.
pub const WRITE_MASK_IS_ABSTRACT: UInt32 = 1 << 11;
/// Indicates if the MinimumSamplingInterval Attribute is writable.
pub const WRITE_MASK_MINIMUM_SAMPLING_INTERVAL: UInt32 = 1 << 12;
/// Indicates if the NodeClass Attribute is writable.
pub const WRITE_MASK_NODE_CLASS: UInt32 = 1 << 13;
/// Indicates if the NodeId Attribute is writable.
pub const WRITE_MASK_NODE_ID: UInt32 = 1 << 14;
/// Indicates if the Symmetric Attribute is writable.
pub const WRITE_MASK_SYMMETRIC: UInt32 = 1 << 15;
/// Indicates if the UserAccessLevel Attribute is writable.
pub const WRITE_MASK_USER_ACCESS_LEVEL: UInt32 = 1 << 16;
/// Indicates if the UserExecutable Attribute is writable.
pub const WRITE_MASK_USER_EXECUTABLE: UInt32 = 1 << 17;
/// Indicates if the UserWriteMask Attribute is writable.
pub const WRITE_MASK_USER_WRITE_MASK: UInt32 = 1 << 18;
/// Indicates if the ValueRank Attribute is writable.
pub const WRITE_MASK_VALUE_RANK: UInt32 = 1 << 19;
/// Indicates if the WriteMask Attribute is writable.
pub const WRITE_MASK_WRITE_MASK: UInt32 = 1 << 20;
/// Indicates if the Value Attribute is writable for a VariableType. It does not apply for Variables
/// since this is handled by the AccessLevel and UserAccessLevel Attributes for the Variable.
/// For Variables this bit shall be set to 0.
pub const WRITE_MASK_VALUE_FOR_VARIABLE_TYPE: UInt32 = 1 << 21;

#[derive(Debug, Clone, PartialEq)]
pub enum Attribute {
    NodeId(NodeId),
    NodeClass(NodeClass),
    BrowseName(QualifiedName),
    DisplayName(LocalizedText),
    Description(LocalizedText),
    WriteMask(UInt32),
    UserWriteMask(UInt32),
    IsAbstract(Boolean),
    Symmetric(Boolean),
    InverseName(LocalizedText),
    ContainsNoLoops(Boolean),
    EventNotifier(Boolean),
    Value(DataValue),
    DataType(NodeId),
    ValueRank(Int32),
    ArrayDimensions(Vec<Int32>),
    AccessLevel(Byte),
    UserAccessLevel(Byte),
    MinimumSamplingInterval(Int32),
    Historizing(Boolean),
    Executable(Boolean),
    UserExecutable(Boolean),
}

impl Attribute {
    pub fn attribute_id(&self) -> AttributeId {
        match self {
            &Attribute::NodeId(_) => AttributeId::NodeId,
            &Attribute::NodeClass(_) => AttributeId::NodeClass,
            &Attribute::BrowseName(_) => AttributeId::BrowseName,
            &Attribute::DisplayName(_) => AttributeId::DisplayName,
            &Attribute::Description(_) => AttributeId::Description,
            &Attribute::WriteMask(_) => AttributeId::WriteMask,
            &Attribute::UserWriteMask(_) => AttributeId::UserWriteMask,
            &Attribute::IsAbstract(_) => AttributeId::IsAbstract,
            &Attribute::Symmetric(_) => AttributeId::Symmetric,
            &Attribute::InverseName(_) => AttributeId::InverseName,
            &Attribute::ContainsNoLoops(_) => AttributeId::ContainsNoLoops,
            &Attribute::EventNotifier(_) => AttributeId::EventNotifier,
            &Attribute::Value(_) => AttributeId::Value,
            &Attribute::DataType(_) => AttributeId::DataType,
            &Attribute::ValueRank(_) => AttributeId::ValueRank,
            &Attribute::ArrayDimensions(_) => AttributeId::ArrayDimensions,
            &Attribute::AccessLevel(_) => AttributeId::AccessLevel,
            &Attribute::UserAccessLevel(_) => AttributeId::UserAccessLevel,
            &Attribute::MinimumSamplingInterval(_) => AttributeId::MinimumSamplingInterval,
            &Attribute::Historizing(_) => AttributeId::Historizing,
            &Attribute::Executable(_) => AttributeId::Executable,
            &Attribute::UserExecutable(_) => AttributeId::UserExecutable,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AttributeId {
    NodeId = 1,
    NodeClass = 2,
    BrowseName = 3,
    DisplayName = 4,
    Description = 5,
    WriteMask = 6,
    UserWriteMask = 7,
    IsAbstract = 8,
    Symmetric = 9,
    InverseName = 10,
    ContainsNoLoops = 11,
    EventNotifier = 12,
    Value = 13,
    DataType = 14,
    ValueRank = 15,
    ArrayDimensions = 16,
    AccessLevel = 17,
    UserAccessLevel = 18,
    MinimumSamplingInterval = 19,
    Historizing = 20,
    Executable = 21,
    UserExecutable = 22,
}

impl AttributeId {
    pub fn from_u32(attribute_id: UInt32) -> Result<AttributeId, ()> {
        let attribute_id = match attribute_id {
            1 => AttributeId::NodeId,
            2 => AttributeId::NodeClass,
            3 => AttributeId::BrowseName,
            4 => AttributeId::DisplayName,
            5 => AttributeId::Description,
            6 => AttributeId::WriteMask,
            7 => AttributeId::UserWriteMask,
            8 => AttributeId::IsAbstract,
            9 => AttributeId::Symmetric,
            10 => AttributeId::InverseName,
            11 => AttributeId::ContainsNoLoops,
            12 => AttributeId::EventNotifier,
            13 => AttributeId::Value,
            14 => AttributeId::DataType,
            15 => AttributeId::ValueRank,
            16 => AttributeId::ArrayDimensions,
            17 => AttributeId::AccessLevel,
            18 => AttributeId::UserAccessLevel,
            19 => AttributeId::MinimumSamplingInterval,
            20 => AttributeId::Historizing,
            21 => AttributeId::Executable,
            22 => AttributeId::UserExecutable,
            _ => {
                debug!("Invalid attribute id {}", attribute_id);
                return Err(());
            }
        };
        Ok(attribute_id)
    }
}

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
    pub fn new(reference_type_id: ReferenceTypeId, node_id: &NodeId) -> Reference{
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
    pub fn new(node_class: NodeClass, node_id: &NodeId, browse_name: &str, display_name: &str, mut attributes: Vec<Attribute>, mut properties: Vec<Property>) -> Base {
        // Mandatory attributes
        let mut attributes_to_add = vec![
            Attribute::NodeClass(node_class),
            Attribute::NodeId(node_id.clone()),
            Attribute::DisplayName(LocalizedText::new("", display_name)),
            Attribute::BrowseName(QualifiedName::new(0, browse_name))
        ];
        attributes_to_add.append(&mut attributes);
        let mut attributes: Vec<Option<Attribute>> = Vec::with_capacity(NUM_ATTRIBUTES);
        for _ in 0..NUM_ATTRIBUTES {
            attributes.push(None);
        }
        for attribute in attributes_to_add {
            let attribute_idx = attribute.attribute_id() as usize - 1;
            attributes[attribute_idx] = Some(attribute);
        }

        let mut base_properties = vec![];
        base_properties.append(&mut properties);


        Base {
            attributes: attributes,
            properties: base_properties,
        }
    }

    fn attribute_idx(attribute_id: AttributeId) -> usize {
        attribute_id as usize - 1
    }

    pub fn set_attribute(&mut self, attribute_id: AttributeId, attribute: Attribute) {
        self.attributes[Base::attribute_idx(attribute_id)] = Some(attribute);
    }

    pub fn unset_attribute(&mut self, attribute_id: AttributeId) {
        self.attributes[Base::attribute_idx(attribute_id)] = None;
    }
}
