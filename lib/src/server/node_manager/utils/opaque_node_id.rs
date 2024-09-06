//! Utils for working with opaque node IDs containing JSON data.

use crate::types::{ByteString, Identifier, NodeId};
use serde::{de::DeserializeOwned, Serialize};

pub fn as_opaque_node_id<T: Serialize>(value: &T, namespace: u16) -> Option<NodeId> {
    let v = serde_json::to_vec(&value).ok()?;
    Some(NodeId {
        namespace,
        identifier: Identifier::ByteString(ByteString { value: Some(v) }),
    })
}

pub fn from_opaque_node_id<T: DeserializeOwned>(id: &NodeId) -> Option<T> {
    let v = match &id.identifier {
        Identifier::ByteString(b) => b.value.as_ref()?,
        _ => return None,
    };
    serde_json::from_slice(&v).ok()
}
