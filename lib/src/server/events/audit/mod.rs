// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! This module implements the audit event types.
//!
//! Note: Due to Rust's lack of inheritance, these types use aggregation and helper macros to expose
//! builder functions on each type in the hierarchy. They're not optimal at all (impls call base impls call base impls in some cases),
//! but they should suffice for the purpose they'll be used for.

use std::sync::Arc;

use crate::sync::*;
use crate::types::*;

use crate::server::{address_space::address_space::AddressSpace, events::event::Event};

pub trait AuditEvent: Event {
    fn parent_node() -> NodeId {
        // TODO Where do audit nodes get put in the address_space?
        NodeId::null()
    }

    /// Returns the kind of event type that this audit event represents. Abstract events should
    /// panic.
    fn event_type_id() -> NodeId;

    fn log_message(&self) -> String;
}

#[macro_use]
pub mod event;
#[macro_use]
pub mod security_event;
#[macro_use]
pub mod session_events;
#[macro_use]
pub mod certificate_events;
pub mod cancel_event;
pub mod node_management_event;

/// The audit log will be responsible for adding audit events to the address space, and potentially logging them
/// to file. All audit events should be raised through `AuditLog` to support any future logging capability.
pub(crate) struct AuditLog {
    address_space: Arc<RwLock<AddressSpace>>,
}

impl AuditLog {
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> AuditLog {
        AuditLog { address_space }
    }

    pub fn raise_and_log<T>(&self, mut event: T) -> Result<NodeId, ()>
    where
        T: AuditEvent + Event,
    {
        let mut address_space = trace_write_lock!(self.address_space);
        let result = event.raise(&mut address_space).map_err(|_| ());
        if result.is_err() {
            error!("Cannot raise an audit event, check audit event entry below to see if there are reasons for this");
        }
        // At this point audit events just go out as log events but smarter logging implementations can always hive these
        // events off to a separate file. Look at demo-server for an example of this.
        info!("Audit Event: {}", event.log_message());
        result
    }
}
