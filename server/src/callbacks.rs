//! Callbacks that a server implementation may register with the library

use std::sync::{Arc, RwLock};

use opcua_types::{
    NodeId,
    status_code::StatusCode,
    service_types::{CallMethodRequest, CallMethodResult},
};

use crate::session::Session;

/// Called by RegisterNodes service
pub trait RegisterNodes {
    /// Called when a client calls the RegisterNodes service. This implementation should return a list
    /// of the same size and order containing node ids corresponding to the input, or aliases. The implementation
    /// should return `BadNodeIdInvalid` if any of the node ids in the input are invalid.
    ///
    /// The call is also given the session that the request was made on. The implementation should
    /// NOT hold a strong reference to this session, but it can make a weak reference if it desires.
    ///
    /// There is no guarantee that the corresponding `OnUnregisterNodes` will be called by the client,
    /// therefore use the weak session references and a periodic check to perform any housekeeping.
    fn register_nodes(&mut self, session: Arc<RwLock<Session>>, nodes_to_register: &[NodeId]) -> Result<Vec<NodeId>, StatusCode>;
}

/// Called by UnregisterNodes service
pub trait UnregisterNodes {
    /// Called when a client calls the UnregisterNodes service. See `OnRegisterNodes` trait for more
    /// information. A client may not call this function, e.g. if connection breaks so do not
    /// count on receiving this to perform any housekeeping.
    ///
    /// The function should not validate the nodes in the request and should just ignore any
    /// unregistered nodes.
    fn unregister_nodes(&mut self, session: Arc<RwLock<Session>>, nodes_to_unregister: &[NodeId]) -> Result<(), StatusCode>;
}

/// Called by the Method service when it invokes a method
pub trait Method {
    /// A method is registered via the address space to a method id and optionally an object id.
    /// When a client sends a CallRequest / CallMethod request, the registered object will
    /// be invoked to handle the call.
    fn call(&mut self, session: &mut Session, request: &CallMethodRequest) -> Result<CallMethodResult, StatusCode>;
}
