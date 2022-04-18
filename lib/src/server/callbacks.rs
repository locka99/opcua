// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Callbacks that a server implementation may register with the library

use std::sync::Arc;

use crate::sync::*;
use crate::types::{
    service_types::{CallMethodRequest, CallMethodResult, TimestampsToReturn},
    status_code::StatusCode,
    AttributeId, DataValue, NodeId, NumericRange, QualifiedName,
};

use super::session::{Session, SessionManager};

/// An attribute getter trait is used to obtain the data value associated with the particular attribute id
/// This allows server implementations to supply a value on demand, usually in response to a polling action
/// such as a monitored item in a subscription.
///
/// `node_id` is the node to which the node belongs
/// `attribute_id` is the attribute of the node to fetch a value for
///
/// Use `max_age` according to the OPC UA Part 4, Table 52 specification to determine how to return
/// a value:
///
/// * 0 = a new value
/// * time in ms for a value less than the specified age
/// * i32::max() or higher to fetch a cached value.
///
pub trait AttributeGetter {
    /// Returns a data value of the specified attribute or none.
    fn get(
        &mut self,
        node_id: &NodeId,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: NumericRange,
        data_encoding: &QualifiedName,
        max_age: f64,
    ) -> Result<Option<DataValue>, StatusCode>;
}

// An attribute setter. Sets the value on the specified attribute
pub trait AttributeSetter {
    /// Sets the attribute on the specified node
    fn set(
        &mut self,
        node_id: &NodeId,
        attribute_id: AttributeId,
        index_range: NumericRange,
        data_value: DataValue,
    ) -> Result<(), StatusCode>;
}

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
    fn register_nodes(
        &mut self,
        session: Arc<RwLock<Session>>,
        nodes_to_register: &[NodeId],
    ) -> Result<Vec<NodeId>, StatusCode>;
}

/// Called by UnregisterNodes service
pub trait UnregisterNodes {
    /// Called when a client calls the UnregisterNodes service. See `OnRegisterNodes` trait for more
    /// information. A client may not call this function, e.g. if connection breaks so do not
    /// count on receiving this to perform any housekeeping.
    ///
    /// The function should not validate the nodes in the request and should just ignore any
    /// unregistered nodes.
    fn unregister_nodes(
        &mut self,
        session: Arc<RwLock<Session>>,
        nodes_to_unregister: &[NodeId],
    ) -> Result<(), StatusCode>;
}

/// Called by the Method service when it invokes a method
pub trait Method {
    /// A method is registered via the address space to a method id and optionally an object id.
    /// When a client sends a CallRequest / CallMethod request, the registered object will
    /// be invoked to handle the call.
    fn call(
        &mut self,
        session_id: &NodeId,
        session_manager: Arc<RwLock<SessionManager>>,
        request: &CallMethodRequest,
    ) -> Result<CallMethodResult, StatusCode>;
}
