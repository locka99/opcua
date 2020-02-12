use std::sync::{Arc, RwLock};

use opcua_crypto::X509;
use opcua_types::*;

use crate::{
    address_space::address_space::AddressSpace,
    events::event::{BaseEventType, Event},
    session::Session,
};

pub trait AuditEvent: Event {}

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

impl AuditEventType {
    pub fn new<R, E, S, T, U>(node_id: R, event_type_id: E, browse_name: S, display_name: T, parent_node: U, time: DateTime) -> Self
        where R: Into<NodeId>,
              E: Into<NodeId>,
              S: Into<QualifiedName>,
              T: Into<LocalizedText>,
              U: Into<NodeId>,
    {
        let now = DateTime::now();
        let action_time_stamp = DateTime::now();
        let server_id = UAString::null();
        Self {
            base: BaseEventType::new(node_id, event_type_id, browse_name, display_name, parent_node, now),
            status: false,
            action_time_stamp,
            server_id,
            client_audit_entry_id: UAString::null(),
            client_user_id: UAString::null(),
        }
    }

    pub fn client_audit_entry_id<T>(mut self, client_audit_entry_id: T) -> Self where T: Into<UAString> {
        self.client_audit_entry_id = client_audit_entry_id.into();
        self
    }

    pub fn client_user_id<T>(mut self, client_user_id: T) -> Self where T: Into<UAString> {
        self.client_user_id = client_user_id.into();
        self
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

impl AuditSecurityEventType {
    pub fn new<R, E, S, T, U>(node_id: R, event_type_id: E, browse_name: S, display_name: T, parent_node: U, time: DateTime) -> Self
        where R: Into<NodeId>,
              E: Into<NodeId>,
              S: Into<QualifiedName>,
              T: Into<LocalizedText>,
              U: Into<NodeId>,
    {
        Self {
            base: AuditEventType::new(node_id, event_type_id, browse_name, display_name, parent_node, time),
        }
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
        !self.session_id.is_null() &&
            self.base.is_valid()
    }

    fn raise(self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        Self::add_property(&node_id, NodeId::next_numeric(ns), "SessionId", "SessionId", self.session_id.clone(), address_space);
        Ok(node_id)
    }
}

impl AuditSessionEventType {
    pub fn new<R, E, S, T, U>(node_id: R, event_type_id: E, browse_name: S, display_name: T, parent_node: U, time: DateTime) -> Self
        where R: Into<NodeId>,
              E: Into<NodeId>,
              S: Into<QualifiedName>,
              T: Into<LocalizedText>,
              U: Into<NodeId>,
    {
        Self {
            base: AuditSecurityEventType::new(node_id, event_type_id, browse_name, display_name, parent_node, time),
            session_id: NodeId::null(),
        }
    }

    pub fn session_id<T>(mut self, session_id: T) -> Self where T: Into<NodeId> {
        self.session_id = session_id.into();
        self
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
        !self.secure_channel_id.is_null() &&
            !self.client_certificate.is_null() &&
            !self.client_certificate_thumbprint.is_null() &&
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

impl AuditCreateSessionEventType {
    pub fn client_certificate(mut self, client_certificate: X509) -> Self {
        self.client_certificate = client_certificate.as_byte_string();
        self.client_certificate_thumbprint = client_certificate.thumbprint().as_hex_string().into();
        self
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

    pub fn log<T>(&self, event: T) -> Result<NodeId, ()> where T: AuditEvent + Event {
        let mut address_space = trace_write_lock_unwrap!(self.address_space);
        event.raise(&mut address_space).map_err(|_| ())
    }
}