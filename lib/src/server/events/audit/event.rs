// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::types::*;

use crate::server::{
    address_space::address_space::AddressSpace,
    events::event::{BaseEventType, Event},
};

use super::AuditEvent;

/// Base type for audit events. Do not raise events of this type
pub(super) struct AuditEventType {
    base: BaseEventType,
    action_time_stamp: UtcTime,
    status: bool,
    server_id: UAString,
    client_audit_entry_id: UAString,
    client_user_id: UAString,
}

impl AuditEvent for AuditEventType {
    fn event_type_id() -> NodeId {
        panic!();
    }

    fn log_message(&self) -> String {
        // Dump out comma-separated key=value pairs in the order they were populated
        self.base
            .properties()
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join(",")
    }
}

impl Event for AuditEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        if self.is_valid() {
            let node_id = self.base.raise(address_space)?;
            let ns = node_id.namespace;
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "ActionTimeStamp",
                "ActionTimeStamp",
                DataTypeId::UtcTime,
                self.action_time_stamp,
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "Status",
                "Status",
                DataTypeId::Boolean,
                self.status,
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "ServerId",
                "ServerId",
                DataTypeId::String,
                self.server_id.clone(),
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "ClientAuditEntryId",
                "ClientAuditEntryId",
                DataTypeId::String,
                self.client_audit_entry_id.clone(),
                address_space,
            );
            self.add_property(
                &node_id,
                NodeId::next_numeric(ns),
                "ClientUserId",
                "ClientUserId",
                DataTypeId::String,
                self.client_user_id.clone(),
                address_space,
            );
            Ok(node_id)
        } else {
            error!("AuditEventType is invalid and will not be inserted");
            Err(())
        }
    }
}

base_event_impl!(AuditEventType, base);

impl AuditEventType {
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
        let action_time_stamp = DateTime::now();
        let server_id = UAString::null();
        let parent_node = Self::parent_node();
        Self {
            base: BaseEventType::new(
                node_id,
                event_type_id,
                browse_name,
                display_name,
                parent_node,
                time,
            ),
            status: false,
            action_time_stamp,
            server_id,
            client_audit_entry_id: UAString::null(),
            client_user_id: UAString::null(),
        }
    }

    pub fn client_audit_entry_id<T>(mut self, client_audit_entry_id: T) -> Self
    where
        T: Into<UAString>,
    {
        self.client_audit_entry_id = client_audit_entry_id.into();
        self
    }

    pub fn client_user_id<T>(mut self, client_user_id: T) -> Self
    where
        T: Into<UAString>,
    {
        self.client_user_id = client_user_id.into();
        self
    }

    pub fn status(mut self, status: bool) -> Self {
        self.status = status;
        self
    }

    pub fn server_id<T>(mut self, server_id: T) -> Self
    where
        T: Into<UAString>,
    {
        self.server_id = server_id.into();
        self
    }

    pub fn action_time_stamp(mut self, action_time_stamp: UtcTime) -> Self {
        self.action_time_stamp = action_time_stamp;
        self
    }
}

macro_rules! audit_event_impl {
    ( $event:ident, $base:ident ) => {
        base_event_impl!($event, $base);

        impl $event {
            pub fn client_audit_entry_id<T>(mut self, client_audit_entry_id: T) -> Self
            where
                T: Into<UAString>,
            {
                self.$base = self.$base.client_audit_entry_id(client_audit_entry_id);
                self
            }

            pub fn client_user_id<T>(mut self, client_user_id: T) -> Self
            where
                T: Into<UAString>,
            {
                self.$base = self.$base.client_user_id(client_user_id);
                self
            }

            pub fn status(mut self, status: bool) -> Self {
                self.$base = self.$base.status(status);
                self
            }

            pub fn server_id<T>(mut self, server_id: T) -> Self
            where
                T: Into<UAString>,
            {
                self.$base = self.$base.server_id(server_id);
                self
            }

            pub fn action_time_stamp(mut self, action_time_stamp: UtcTime) -> Self {
                self.$base = self.$base.action_time_stamp(action_time_stamp);
                self
            }
        }
    };
}
