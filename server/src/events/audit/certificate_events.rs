use opcua_types::*;

use crate::{
    address_space::address_space::AddressSpace,
    events::event::Event,
};

use super::{
    AuditEvent,
    security_event::AuditSecurityEventType,
};

pub struct AuditCertificateEventType {
    base: AuditSecurityEventType,
    certificate: ByteString,
}

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

impl AuditEvent for AuditCertificateEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateEventType.into()
    }
}

impl AuditEvent for AuditCertificateEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateEventType.into()
    }
}

audit_security_event_impl!(AuditCertificateEventType, base);

impl AuditCertificateEventType {
    pub fn new<R, E, S, T>(node_id: R, event_type_id: E, browse_name: S, display_name: T, time: DateTime) -> Self
        where R: Into<NodeId>,
              E: Into<NodeId>,
              S: Into<QualifiedName>,
              T: Into<LocalizedText>,
    {
        Self {
            base: AuditSecurityEventType::new(node_id, event_type_id, browse_name, display_name, time),
            certificate: ByteString::null(),
        }
    }

    pub fn certificate(mut self, certificate: ByteString) -> Self {
        self.certificate = certificate;
        self
    }
}

macro_rules! audit_certificate_event_impl {
    ( $event:ident, $base:ident ) => {
        audit_security_event_impl!($event, $base);

        impl $event {
            pub fn certificate(mut self, certificate: ByteString) -> Self {
                self.$base = self.$base.certificate(certificate);
                self
            }
        }
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

impl AuditEvent for AuditCertificateDataMismatchEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateDataMismatchEventType.into()
    }
}

impl AuditEvent for AuditCertificateDataMismatchEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateDataMismatchEventType.into()
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

impl AuditEvent for AuditCertificateExpiredEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateExpiredEventType.into()
    }
}

impl AuditEvent for AuditCertificateExpiredEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateExpiredEventType.into()
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

impl AuditEvent for AuditCertificateInvalidEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateInvalidEventType.into()
    }
}

impl AuditEvent for AuditCertificateInvalidEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateInvalidEventType.into()
    }
}

audit_certificate_event_impl!(AuditCertificateInvalidEventType, base);

impl AuditCertificateInvalidEventType {
    pub fn new() -> Self {
        Self {
            base:
        }
    }
}

impl AuditCertificateInvalidEventType {
    pub fn new<R, S, T>(node_id: R, time: DateTime) -> Self
        where R: Into<NodeId>,
    {
        let event_type_id = Self::event_type_id();
        let browse_name = "AuditCertificateInvalidEventType";
        let display_name = "AuditCertificateInvalidEventType";
        Self {
            base: AuditCertificateEventType::new(node_id, event_type_id, browse_name, display_name, time),
        }
    }
}

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

impl AuditEvent for AuditCertificateUntrustedEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateUntrustedEventType.into()
    }
}

impl AuditEvent for AuditCertificateUntrustedEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateUntrustedEventType.into()
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

impl AuditEvent for AuditCertificateRevokedEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateRevokedEventType.into()
    }
}

impl AuditEvent for AuditCertificateRevokedEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateRevokedEventType.into()
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

impl AuditEvent for AuditCertificateMismatchEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateMismatchEventType.into()
    }
}

impl AuditEvent for AuditCertificateMismatchEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCertificateMismatchEventType.into()
    }
}

audit_certificate_event_impl!(AuditCertificateMismatchEventType, base);
