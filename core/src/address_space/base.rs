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
    DisplayName(LocalizedText),
    NodeId(NodeId),
    NodeClass(NodeClass),
    Description(LocalizedText),
    BrowseName(QualifiedName),
    UserWriteMask(UInt32),
    WriteMask(UInt32),
    UserAccessLevel(Byte),
    AccessLevel(Byte),
    IsAbstract(Boolean),
    Symmetric(Boolean),
    InverseName(LocalizedText),
    Executable(Boolean),
    UserExecutable(Boolean),
    // Value(DataType),
    ValueRank(Int32),
    ArrayDimensions(Vec<Int32>),
    Historizing(Boolean),
    MinimumSamplingInterval(Int32),
    EventNotifier(Boolean),
    ContainsNoLoops(Boolean),
}

/// The NodeId is the target node. The reference is held in a list by the source node.
/// The target node does not need to exist.
#[derive(Debug, Clone, PartialEq)]
pub enum Reference {
    References(NodeId),
    NonHierarchicalReferences(NodeId),
    HierarchicalReferences(NodeId),
    HasChild(NodeId),
    Organizes(NodeId),
    HasEventSource(NodeId),
    HasModellingRule(NodeId),
    HasEncoding(NodeId),
    HasDescription(NodeId),
    HasTypeDefinition(NodeId),
    GeneratesEvent(NodeId),
    Aggregates(NodeId),
    HasSubtype(NodeId),
    HasProperty(NodeId),
    HasComponent(NodeId),
    HasNotifier(NodeId),
    HasOrderedComponent(NodeId),
    FromState(NodeId),
    ToState(NodeId),
    HasCause(NodeId),
    HasEffect(NodeId),
    HasHistoricalConfiguration(NodeId),
    HasSubStateMachine(NodeId),
    AlwaysGeneratesEvent(NodeId),
    HasTrueSubState(NodeId),
    HasFalseSubState(NodeId),
    HasCondition(NodeId),
}

impl Reference {
    pub fn reference_type_id(&self) -> ReferenceTypeId {
        match self {
            &Reference::References(_) => ReferenceTypeId::References,
            &Reference::NonHierarchicalReferences(_) => ReferenceTypeId::NonHierarchicalReferences,
            &Reference::HierarchicalReferences(_) => ReferenceTypeId::HierarchicalReferences,
            &Reference::HasChild(_) => ReferenceTypeId::HasChild,
            &Reference::Organizes(_) => ReferenceTypeId::Organizes,
            &Reference::HasEventSource(_) => ReferenceTypeId::HasEventSource,
            &Reference::HasModellingRule(_) => ReferenceTypeId::HasModellingRule,
            &Reference::HasEncoding(_) => ReferenceTypeId::HasEncoding,
            &Reference::HasDescription(_) => ReferenceTypeId::HasDescription,
            &Reference::HasTypeDefinition(_) => ReferenceTypeId::HasTypeDefinition,
            &Reference::GeneratesEvent(_) => ReferenceTypeId::GeneratesEvent,
            &Reference::Aggregates(_) => ReferenceTypeId::Aggregates,
            &Reference::HasSubtype(_) => ReferenceTypeId::HasSubtype,
            &Reference::HasProperty(_) => ReferenceTypeId::HasProperty,
            &Reference::HasComponent(_) => ReferenceTypeId::HasComponent,
            &Reference::HasNotifier(_) => ReferenceTypeId::HasNotifier,
            &Reference::HasOrderedComponent(_) => ReferenceTypeId::HasOrderedComponent,
            &Reference::FromState(_) => ReferenceTypeId::FromState,
            &Reference::ToState(_) => ReferenceTypeId::ToState,
            &Reference::HasCause(_) => ReferenceTypeId::HasCause,
            &Reference::HasEffect(_) => ReferenceTypeId::HasEffect,
            &Reference::HasHistoricalConfiguration(_) => ReferenceTypeId::HasHistoricalConfiguration,
            &Reference::HasSubStateMachine(_) => ReferenceTypeId::HasSubStateMachine,
            &Reference::AlwaysGeneratesEvent(_) => ReferenceTypeId::AlwaysGeneratesEvent,
            &Reference::HasTrueSubState(_) => ReferenceTypeId::HasTrueSubState,
            &Reference::HasFalseSubState(_) => ReferenceTypeId::HasFalseSubState,
            &Reference::HasCondition(_) => ReferenceTypeId::HasCondition,
        }
    }

    pub fn node_id(&self) -> &NodeId {
        match self {
            &Reference::References(ref node_id) => node_id,
            &Reference::NonHierarchicalReferences(ref node_id) => node_id,
            &Reference::HierarchicalReferences(ref node_id) => node_id,
            &Reference::HasChild(ref node_id) => node_id,
            &Reference::Organizes(ref node_id) => node_id,
            &Reference::HasEventSource(ref node_id) => node_id,
            &Reference::HasModellingRule(ref node_id) => node_id,
            &Reference::HasEncoding(ref node_id) => node_id,
            &Reference::HasDescription(ref node_id) => node_id,
            &Reference::HasTypeDefinition(ref node_id) => node_id,
            &Reference::GeneratesEvent(ref node_id) => node_id,
            &Reference::Aggregates(ref node_id) => node_id,
            &Reference::HasSubtype(ref node_id) => node_id,
            &Reference::HasProperty(ref node_id) => node_id,
            &Reference::HasComponent(ref node_id) => node_id,
            &Reference::HasNotifier(ref node_id) => node_id,
            &Reference::HasOrderedComponent(ref node_id) => node_id,
            &Reference::FromState(ref node_id) => node_id,
            &Reference::ToState(ref node_id) => node_id,
            &Reference::HasCause(ref node_id) => node_id,
            &Reference::HasEffect(ref node_id) => node_id,
            &Reference::HasHistoricalConfiguration(ref node_id) => node_id,
            &Reference::HasSubStateMachine(ref node_id) => node_id,
            &Reference::AlwaysGeneratesEvent(ref node_id) => node_id,
            &Reference::HasTrueSubState(ref node_id) => node_id,
            &Reference::HasFalseSubState(ref node_id) => node_id,
            &Reference::HasCondition(ref node_id) => node_id,
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
    fn add_reference(&mut self, reference: Reference);
    fn references(&self) -> &Vec<Reference>;
}

/// Base is the functionality that all kinds of nodes need. Part 3, diagram B.4
#[derive(Debug, Clone, PartialEq)]
pub struct Base {
    // TODO number of attributes is fixed per type so it'd be more efficient to hold an array of options
    // and use an index find each of them. Depends how much they're used really
    pub attributes: Vec<Attribute>,
    pub references: Vec<Reference>,
    pub properties: Vec<Property>,
}


impl Node for Base {
    /// Returns the node class
    fn node_class(&self) -> NodeClass {
        find_attribute_mandatory!(self, NodeClass);
    }

    fn node_id(&self) -> NodeId {
        find_attribute_mandatory!(self, NodeId);
    }

    fn browse_name(&self) -> QualifiedName {
        find_attribute_mandatory!(self, BrowseName);
    }

    fn display_name(&self) -> LocalizedText {
        find_attribute_mandatory!(self, DisplayName);
    }

    fn description(&self) -> Option<LocalizedText> {
        find_attribute_optional!(self, Description);
    }

    fn write_mask(&self) -> Option<UInt32> {
        find_attribute_optional!(self, WriteMask);
    }

    fn user_write_mask(&self) -> Option<UInt32> {
        find_attribute_optional!(self, UserWriteMask);
    }

    fn add_reference(&mut self, reference: Reference) {
        self.references.push(reference);
    }

    fn references(&self) -> &Vec<Reference> {
        &self.references
    }
}

impl Base {
    pub fn new(node_class: NodeClass, node_id: &NodeId, browse_name: &str, display_name: &str, mut attributes: Vec<Attribute>, mut references: Vec<Reference>, mut properties: Vec<Property>) -> Base {
        // Mandatory attributes
        let mut base_attributes = vec![
            Attribute::NodeClass(node_class),
            Attribute::NodeId(node_id.clone()),
            Attribute::DisplayName(LocalizedText::new("", display_name)),
            Attribute::BrowseName(QualifiedName::new(0, browse_name))
        ];
        // Optional attributes are only added if the caller supplies the
        base_attributes.append(&mut attributes);

        let mut base_references = vec![];
        base_references.append(&mut references);

        let mut base_properties = vec![];
        base_properties.append(&mut properties);

        Base {
            attributes: base_attributes,
            references: base_references,
            properties: base_properties,
        }
    }
}
