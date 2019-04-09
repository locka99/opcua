//! Callbacks that a server implementation may register with the library

use std::sync::{Arc, RwLock};

use opcua_types::{
    NodeId,
    status_code::StatusCode,
};

use crate::session::Session;

/// Called by RegisterNodes service
pub trait OnRegisterNodes {
    /// Called when a client calls the RegisterNodes service. This implementation should return a list
    /// of the same size and order containing node ids corresponding to the input, or aliases. The implementation
    /// should return `BadNodeIdInvalid` if any of the node ids in the input are invalid.
    ///
    /// The call is also given the session that the request was made on. The implementation should
    /// NOT hold a strong reference to this session, but it can make a weak reference if it desires.
    ///
    /// There is no guarantee that the corresponding `OnUnregisterNodes` will be called by the client,
    /// therefore use the weak session references and a periodic check to perform any housekeeping.
    fn on_register_nodes(&mut self, session: Arc<RwLock<Session>>, nodes_to_register: &[NodeId]) -> Result<Vec<NodeId>, StatusCode>;
}

/// Called by UnregisterNodes service
pub trait OnUnregisterNodes {
    /// Called when a client calls the UnregisterNodes service. See `OnRegisterNodes` trait for more
    /// information.
    fn on_unregister_nodes(&mut self, session: Arc<RwLock<Session>>, nodes_to_unregister: &[NodeId]) -> Result<(), StatusCode>;
}
