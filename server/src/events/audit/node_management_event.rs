use opcua_types::*;

use crate::{
    address_space::address_space::AddressSpace,
    events::event::Event,
};

use super::{
    event::AuditEventType,
    AuditEvent,
};

pub struct AuditNodeManagementEventType {
    base: AuditEventType
}

impl Event for AuditNodeManagementEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

impl AuditEvent for AuditNodeManagementEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditNodeManagementEventType.into()
    }
}

impl AuditEvent for AuditNodeManagementEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditNodeManagementEventType.into()
    }
}

audit_event_impl!(AuditNodeManagementEventType, base);
