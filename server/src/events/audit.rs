use opcua_types::*;

use crate::{
    address_space::address_space::AddressSpace,
    events::event::{BaseEventType, Event},
};

pub(crate) struct AuditLog {}

/// Base type for audit events. Do not raise events of this type
struct AuditEventType {
    base: BaseEventType,
    action_time_stamp: UtcTime,
    status: bool,
    server_id: UAString,
    client_audit_entry_id: UAString,
    client_user_id: UAString,
}

impl Event for AuditEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err>
    {
        if self.is_valid() {
            let node_id = self.base.raise(address_space)?;
            let ns = node_id.namespace;
            Self::add_property(&node_id, NodeId::next_numeric(ns), "ActionTimeStamp", "ActionTimeStamp", self.action_time_stamp.clone(), address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "Status", "Status", self.status, address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "ServerId", "ServerId", self.server_id.clone(), address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "ClientAuditEntryId", "ClientAuditEntryId", self.client_audit_entry_id.clone(), address_space);
            Self::add_property(&node_id, NodeId::next_numeric(ns), "ClientUserId", "ClientUserId", self.client_user_id.clone(), address_space);
            Ok(node_id)
        } else {
            error!("AuditEventType is invalid and will not be inserted");
            Err(())
        }
    }
}

/// Base type for audit security events. Do not raise events of this type
struct AuditSecurityEventType {
    base: AuditEventType
}

impl Event for AuditSecurityEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        self.base.raise(address_space)
    }
}

/// Base type for audit session events. Do not raise events of this type
struct AuditSessionEventType {
    base: AuditSecurityEventType,
    session_id: NodeId,
}

impl Event for AuditSessionEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        Self::add_property(&node_id, NodeId::next_numeric(ns), "SessionId", "SessionId", self.session_id.clone(), address_space);
        Ok(node_id)
    }
}

pub struct AuditCreateSessionEventType {
    base: AuditSessionEventType,
    secure_channel_id: UAString,
    client_certificate: ByteString,
    client_certificate_thumbprint: UAString,
    revised_session_timeout: Duration,
}

impl Event for AuditCreateSessionEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        Self::add_property(&node_id, NodeId::next_numeric(ns), "SecureChannelId", "SecureChannelId", self.secure_channel_id.clone(), address_space);
        Self::add_property(&node_id, NodeId::next_numeric(ns), "ClientCertificate", "ClientCertificate", self.client_certificate.clone(), address_space);
        Self::add_property(&node_id, NodeId::next_numeric(ns), "ClientCertificateThumbprint", "ClientCertificateThumbprint", self.client_certificate_thumbprint.clone(), address_space);
        Self::add_property(&node_id, NodeId::next_numeric(ns), "RevisedSessionTimeout", "RevisedSessionTimeout", self.revised_session_timeout, address_space);
        Ok(node_id)
    }
}

pub struct AuditActivateSessionEventType {
    base: AuditSessionEventType,
    client_software_certificates: SignedSoftwareCertificate,
    // pub user_identity_token: References,
    secure_channel_id: UAString,
}

impl Event for AuditActivateSessionEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        // TODO client software certificates (extension object i=344)
        // TODO user identity token (extension object i=316)
        Self::add_property(&node_id, NodeId::next_numeric(ns), "SecureChannelId", "SecureChannelId", self.secure_channel_id.clone(), address_space);
        Ok(node_id)
    }
}

pub struct AuditCancelEventType {
    base: AuditSessionEventType,
    request_handle: u32,
}

impl Event for AuditCancelEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        Self::add_property(&node_id, NodeId::next_numeric(ns), "RequestHandle", "RequestHandle", self.request_handle, address_space);
        Ok(node_id)
    }
}

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

impl AuditLog {}