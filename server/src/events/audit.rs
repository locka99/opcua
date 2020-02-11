use std::sync::{Arc, RwLock};

use opcua_types::*;

use crate::{
    address_space::address_space::AddressSpace,
    events::event::{BaseEventType, Event},
    session::Session,
};

trait AuditEvent: Event {}

/// Base type for audit events. Do not raise events of this type
struct AuditEventType {
    base: BaseEventType,
    action_time_stamp: UtcTime,
    status: bool,
    server_id: UAString,
    client_audit_entry_id: UAString,
    client_user_id: UAString,
}

impl AuditEvent for AuditEventType {}

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

impl AuditEvent for AuditSecurityEventType {}

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

impl AuditEvent for AuditSessionEventType {}

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

impl AuditEvent for AuditCreateSessionEventType {}

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
    client_software_certificates: Vec<SignedSoftwareCertificate>,
    user_identity_token: UserIdentityToken,
    secure_channel_id: UAString,
}

impl AuditEvent for AuditActivateSessionEventType {}

impl Event for AuditActivateSessionEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        // Client software certificates is an array of extension objects (extension object i=344)
        let client_software_certificates =
            self.client_software_certificates.iter().map(|c| {
                Variant::from(ExtensionObject::from_encodable(ObjectId::SignedSoftwareCertificate_Encoding_DefaultBinary, c))
            }).collect::<Vec<_>>();
        Self::add_property(&node_id, NodeId::next_numeric(ns), "ClientSoftwareCertificates", "ClientSoftwareCertificates", client_software_certificates, address_space);

        // User identity token (extension object i=316)
        let user_identity_token = ExtensionObject::from_encodable(ObjectId::UserIdentityToken_Encoding_DefaultBinary, &self.user_identity_token);
        Self::add_property(&node_id, NodeId::next_numeric(ns), "UserIdentityToken", "UserIdentityToken", user_identity_token, address_space);

        Self::add_property(&node_id, NodeId::next_numeric(ns), "SecureChannelId", "SecureChannelId", self.secure_channel_id.clone(), address_space);
        Ok(node_id)
    }
}

pub struct AuditCancelEventType {
    base: AuditSessionEventType,
    request_handle: u32,
}

impl AuditEvent for AuditCancelEventType {}

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

pub struct AuditCertificateDataMismatchEventType {
    base: AuditCertificateEventType
}

impl AuditEvent for AuditCertificateDataMismatchEventType {}

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

impl AuditEvent for AuditCertificateExpiredEventType {}

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

impl AuditEvent for AuditCertificateInvalidEventType {}

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

impl AuditEvent for AuditCertificateUntrustedEventType {}

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

impl AuditEvent for AuditCertificateRevokedEventType {}

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

impl AuditEvent for AuditCertificateMismatchEventType {}

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

pub(crate) struct AuditLog {
    address_space: Arc<RwLock<AddressSpace>>,
}

impl AuditLog {
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> AuditLog {
        AuditLog {
            address_space
        }
    }

    fn log<T>(&self, event: T) -> Result<NodeId, ()> where T: AuditEvent + Event {
        let mut address_space = trace_write_lock_unwrap!(self.address_space);
        event.raise(&mut address_space).map_err(|_| ())
    }

    pub fn log_open_secure_channel(&self, session: Arc<RwLock<Session>>) {}

    pub fn log_cancel(&self, session: Arc<RwLock<Session>>, audit_entry_id: &str, client_entry_id: &UAString, request_handle: u32) {}
    pub fn log_update_method(&self, session: Arc<RwLock<Session>>) {}

    pub fn log_activate_session(&self) {}
    pub fn log_create_session(&self) {}
    pub fn log_url_mismatch(&self) {}

    pub fn log_certificate_data_mismatch(&self) {}
    pub fn log_certificate_expired(&self) {}
    pub fn log_certificate_invalid(&self) {}
    pub fn log_certificate_untrusted(&self) {}
    pub fn log_certificate_revoked(&self) {}
    pub fn log_certificate_mismatch(&self) {}

    pub fn log_add_nodes(&self) {}
    pub fn log_delete_nodes(&self) {}
    pub fn log_add_references(&self) {}
    pub fn log_delete_references(&self) {}

    pub fn log_write_update(&self) {}
    pub fn log_history_update(&self) {}
}