// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::types::*;

use crate::server::{address_space::address_space::AddressSpace, events::event::Event};

use super::{event::AuditEventType, AuditEvent};

pub struct AuditNodeManagementEventType {
    base: AuditEventType,
}

impl Event for AuditNodeManagementEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

impl AuditEvent for AuditNodeManagementEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditNodeManagementEventType.into()
    }

    fn log_message(&self) -> String {
        self.base.log_message()
    }
}

audit_event_impl!(AuditNodeManagementEventType, base);
