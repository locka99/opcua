// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::types::*;

use crate::server::{address_space::address_space::AddressSpace, events::event::Event};

use super::{event::AuditEventType, AuditEvent};

/// Base type for audit security events. Do not raise events of this type
pub(super) struct AuditSecurityEventType {
    base: AuditEventType,
}

impl AuditEvent for AuditSecurityEventType {
    fn event_type_id() -> NodeId {
        panic!()
    }

    fn log_message(&self) -> String {
        self.base.log_message()
    }
}

impl Event for AuditSecurityEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

audit_event_impl!(AuditSecurityEventType, base);

impl AuditSecurityEventType {
    pub fn new<R, E, S, T>(
        node_id: R,
        event_type_id: E,
        browse_name: S,
        display_name: T,
        time: DateTime,
    ) -> Self
    where
        R: Into<NodeId>,
        E: Into<NodeId>,
        S: Into<QualifiedName>,
        T: Into<LocalizedText>,
    {
        Self {
            base: AuditEventType::new(node_id, event_type_id, browse_name, display_name, time),
        }
    }
}

macro_rules! audit_security_event_impl {
    ( $event:ident, $base:ident ) => {
        audit_event_impl!($event, $base);
    };
}
