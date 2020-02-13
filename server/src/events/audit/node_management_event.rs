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

impl AuditEvent for AuditNodeManagementEventType {}

impl Event for AuditNodeManagementEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}