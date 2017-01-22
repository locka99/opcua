use types::*;
use services::*;
use address_space::*;

pub struct Attribute {}

pub struct Property {}

/// Implemented by BaseNode and all derived Node types
pub trait Node {
    fn node_class(&self) -> NodeClass;
    fn node_id(&self) -> NodeId;
    fn browse_name(&self) -> String;
    fn display_name(&self) -> String;
    fn description(&self) -> String;
}

/// BaseNode is the functionality that all kinds of nodes need
pub struct BaseNode {
    pub node_id: NodeId,
    pub browse_name: String,
    // TODO localized display name, max 512 chars
    pub display_name: String,
    pub description: String,
    pub write_mask: UInt32,
    pub attributes: Vec<Attribute>,
    pub references: Vec<Reference>,
    pub properties: Vec<Property>,
}

impl Node for BaseNode {
    /// Returns the node class
    fn node_class(&self) -> NodeClass {
        NodeClass::Unspecified
    }
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }
    fn browse_name(&self) -> String {
        self.browse_name.clone()
    }
    fn display_name(&self) -> String {
        self.display_name.clone()
    }
    fn description(&self) -> String {
        self.description.clone()
    }
}

impl BaseNode {
    pub fn new(node_id: &NodeId, browse_name: &str, display_name: &str) -> BaseNode {
        BaseNode {
            node_id: node_id.clone(),
            browse_name: browse_name.to_string(),
            display_name: display_name.to_string(),
            description: "".to_string(),
            write_mask: 0,
            attributes: vec![],
            references: vec![],
            properties: vec![],
        }
    }
}