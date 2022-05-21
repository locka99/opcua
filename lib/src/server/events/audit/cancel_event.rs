// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::types::*;

use crate::server::{address_space::address_space::AddressSpace, events::event::Event};

use super::{session_events::AuditSessionEventType, AuditEvent};

pub struct AuditCancelEventType {
    base: AuditSessionEventType,
    request_handle: u32,
}

impl AuditEvent for AuditCancelEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCancelEventType.into()
    }

    fn log_message(&self) -> String {
        self.base.log_message()
    }
}

impl Event for AuditCancelEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "RequestHandle",
            "RequestHandle",
            DataTypeId::UInt32,
            self.request_handle,
            address_space,
        );
        Ok(node_id)
    }
}

audit_session_event_impl!(AuditCancelEventType, base);

impl AuditCancelEventType {
    pub fn request_handle(mut self, request_handle: u32) -> Self {
        self.request_handle = request_handle;
        self
    }
}
