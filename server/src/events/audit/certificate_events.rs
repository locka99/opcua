use opcua_types::*;

use crate::{
    address_space::address_space::AddressSpace,
    events::event::Event,
};

use super::{
    security_event::AuditSecurityEventType,
    AuditEvent,
};

pub struct AuditCertificateEventType {
    base: AuditSecurityEventType,
    certificate: ByteString,
}

impl AuditEvent for AuditCertificateEventType {}

impl Event for AuditCertificateEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        Self::add_property(&node_id, NodeId::next_numeric(ns), "Certificate", "Certificate", self.certificate.clone(), address_space);
        Ok(node_id)
    }
}

audit_security_event_impl!(AuditCertificateEventType, base);

macro_rules! audit_certificate_event_impl {
    ( $event:ident, $base:ident ) => {
        audit_security_event_impl!($event, $base);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuditCertificateDataMismatchEventType {
    base: AuditCertificateEventType
}

impl Event for AuditCertificateDataMismatchEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

audit_certificate_event_impl!(AuditCertificateDataMismatchEventType, base);

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuditCertificateExpiredEventType {
    base: AuditCertificateEventType
}

impl Event for AuditCertificateExpiredEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

audit_certificate_event_impl!(AuditCertificateExpiredEventType, base);

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuditCertificateInvalidEventType {
    base: AuditCertificateEventType
}

impl Event for AuditCertificateInvalidEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

audit_certificate_event_impl!(AuditCertificateInvalidEventType, base);

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuditCertificateUntrustedEventType {
    base: AuditCertificateEventType
}

impl Event for AuditCertificateUntrustedEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

audit_certificate_event_impl!(AuditCertificateUntrustedEventType, base);

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuditCertificateRevokedEventType {
    pub base: AuditCertificateEventType
}

impl Event for AuditCertificateRevokedEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

audit_certificate_event_impl!(AuditCertificateRevokedEventType, base);

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuditCertificateMismatchEventType {
    base: AuditCertificateEventType
}

impl Event for AuditCertificateMismatchEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

audit_certificate_event_impl!(AuditCertificateMismatchEventType, base);
