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

/// All the AuditCertificateXXXEventType derived frmo AuditCertificateEventType can be implemented from a macro
macro_rules! audit_certificate_event_impl {
    ( $event:ident ) => {
        audit_security_event_impl!($event, base);

        pub struct $event {
            base: AuditCertificateEventType
        }

        impl Event for $event {
            type Err = ();

            fn is_valid(&self) -> bool {
                self.base.is_valid()
            }

            fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
                self.base.raise(address_space)
            }
        }

        impl AuditEvent for $event {
            fn event_type_id() -> NodeId {
                ObjectTypeId::$event.into()
            }
        }

        impl $event {
            pub fn certificate(mut self, certificate: ByteString) -> Self {
                self.base = self.base.certificate(certificate);
                self
            }
        }
    }
}

audit_certificate_event_impl!(AuditCertificateDataMismatchEventType);
audit_certificate_event_impl!(AuditCertificateExpiredEventType);
audit_certificate_event_impl!(AuditCertificateInvalidEventType);
audit_certificate_event_impl!(AuditCertificateUntrustedEventType);
audit_certificate_event_impl!(AuditCertificateRevokedEventType);
audit_certificate_event_impl!(AuditCertificateMismatchEventType);
