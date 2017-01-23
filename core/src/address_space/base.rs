use types::*;
use services::*;
use address_space::*;

// Attributes as defined in Part 4, Figure B.7

// Attributes sometimes required and sometimes optional

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

#[derive(Debug, Clone, PartialEq)]
pub struct Property {}

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
}

/// Base is the functionality that all kinds of nodes need. Part 3, diagram B.4
#[derive(Debug, Clone, PartialEq)]
pub struct Base {
    pub attributes: Vec<Attribute>,
    pub references: Vec<Reference>,
    pub properties: Vec<Property>,
}

impl Node for Base {
    /// Returns the node class
    fn node_class(&self) -> NodeClass {
        for a in self.attributes.iter() {
            if let &Attribute::NodeClass(ref value) = a { return value.clone(); }
        }
        panic!("NodeClass is a mandatory value so where is it?");
    }

    fn node_id(&self) -> NodeId {
        for a in self.attributes.iter() {
            if let &Attribute::NodeId(ref value) = a { return value.clone(); }
        }
        panic!("NodeId is a mandatory value so where is it?");
    }

    fn browse_name(&self) -> QualifiedName {
        for a in self.attributes.iter() {
            if let &Attribute::BrowseName(ref value) = a { return value.clone(); }
        }
        panic!("BrowseName is a mandatory value so where is it?");
    }

    fn display_name(&self) -> LocalizedText {
        for a in self.attributes.iter() {
            if let &Attribute::DisplayName(ref value) = a { return value.clone(); }
        }
        panic!("DisplayName is a mandatory value so where is it?");
    }

    fn description(&self) -> Option<LocalizedText> {
        for a in self.attributes.iter() {
            if let &Attribute::Description(ref value) = a { return Some(value.clone()); }
        }
        None
    }

    fn write_mask(&self) -> Option<UInt32> {
        for a in self.attributes.iter() {
            if let &Attribute::WriteMask(ref value) = a { return Some(value.clone()); }
        }
        None
    }

    fn user_write_mask(&self) -> Option<UInt32> {
        for a in self.attributes.iter() {
            if let &Attribute::UserWriteMask(ref value) = a { return Some(value.clone()); }
        }
        None
    }
}

impl Base {
    pub fn new(node_class: NodeClass, node_id: &NodeId, browse_name: &str, display_name: &str, mut attrs: Vec<Attribute>) -> Base {
        // Make attributes from base node and input
        let mut attributes = vec![
            Attribute::NodeClass(node_class),
            Attribute::NodeId(node_id.clone()),
            Attribute::DisplayName(LocalizedText::new("", display_name)),
            Attribute::BrowseName(QualifiedName::new(0, browse_name))
        ];
        attributes.append(&mut attrs);
        Base {
            attributes: attributes,
            references: vec![],
            properties: vec![],
        }
    }
}
