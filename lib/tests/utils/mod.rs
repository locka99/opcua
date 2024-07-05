mod node_manager;
mod tester;

pub const CLIENT_USERPASS_ID: &str = "sample1";
pub const CLIENT_X509_ID: &str = "x509";

pub use node_manager::*;
use opcua::types::{AttributeId, NodeId, ReadValueId};
pub use tester::*;

#[allow(unused)]
pub fn read_value_id(attribute: AttributeId, id: impl Into<NodeId>) -> ReadValueId {
    let node_id = id.into();
    ReadValueId {
        node_id,
        attribute_id: attribute as u32,
        ..Default::default()
    }
}

#[allow(unused)]
pub fn read_value_ids(attributes: &[AttributeId], id: impl Into<NodeId>) -> Vec<ReadValueId> {
    let node_id = id.into();
    attributes
        .iter()
        .map(|a| read_value_id(*a, &node_id))
        .collect()
}
