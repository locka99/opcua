// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use crate::crypto::X509;
use crate::types::*;

use crate::server::{address_space::address_space::AddressSpace, events::event::Event};

use super::{security_event::AuditSecurityEventType, AuditEvent};

/// Base type for audit session events. Do not raise events of this type
pub struct AuditSessionEventType {
    base: AuditSecurityEventType,
    session_id: NodeId,
}

pub enum AuditCloseSessionReason {
    CloseSession,
    Timeout,
    Terminated,
}

impl AuditCloseSessionReason {
    pub fn source_name(&self) -> String {
        match self {
            AuditCloseSessionReason::CloseSession => "Session/CloseSession",
            AuditCloseSessionReason::Timeout => "Session/Timeout",
            AuditCloseSessionReason::Terminated => "Session/Terminated",
        }
        .into()
    }
}

impl AuditEvent for AuditSessionEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditSessionEventType.into()
    }

    fn log_message(&self) -> String {
        self.base.log_message()
    }
}

impl Event for AuditSessionEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        !self.session_id.is_null() && self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "SessionId",
            "SessionId",
            DataTypeId::NodeId,
            self.session_id.clone(),
            address_space,
        );
        Ok(node_id)
    }
}

audit_security_event_impl!(AuditSessionEventType, base);

impl AuditSessionEventType {
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
            base: AuditSecurityEventType::new(
                node_id,
                event_type_id,
                browse_name,
                display_name,
                time,
            ),
            session_id: NodeId::null(),
        }
    }

    pub fn new_close_session<R>(node_id: R, time: DateTime, reason: AuditCloseSessionReason) -> Self
    where
        R: Into<NodeId>,
    {
        Self::new(
            node_id,
            Self::event_type_id(),
            "AuditSessionEventType",
            "AuditSessionEventType",
            time,
        )
        .source_name(reason.source_name())
    }

    pub fn session_id<T>(mut self, session_id: T) -> Self
    where
        T: Into<NodeId>,
    {
        self.session_id = session_id.into();
        self
    }
}

macro_rules! audit_session_event_impl {
    ( $event:ident, $base:ident ) => {
        audit_security_event_impl!($event, $base);

        impl $event {
            pub fn session_id<T>(mut self, session_id: T) -> $event
            where
                T: Into<NodeId>,
            {
                self.$base = self.$base.session_id(session_id);
                self
            }
        }
    };
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuditCreateSessionEventType {
    base: AuditSessionEventType,
    secure_channel_id: UAString,
    client_certificate: ByteString,
    client_certificate_thumbprint: UAString,
    revised_session_timeout: Duration,
}

impl AuditEvent for AuditCreateSessionEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditCreateSessionEventType.into()
    }

    fn log_message(&self) -> String {
        self.base.log_message()
    }
}

impl Event for AuditCreateSessionEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        !self.secure_channel_id.is_null()
            && !self.client_certificate.is_null()
            && !self.client_certificate_thumbprint.is_null()
            && self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "SecureChannelId",
            "SecureChannelId",
            DataTypeId::String,
            self.secure_channel_id.clone(),
            address_space,
        );
        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "ClientCertificate",
            "ClientCertificate",
            DataTypeId::ByteString,
            self.client_certificate.clone(),
            address_space,
        );
        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "ClientCertificateThumbprint",
            "ClientCertificateThumbprint",
            DataTypeId::String,
            self.client_certificate_thumbprint.clone(),
            address_space,
        );
        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "RevisedSessionTimeout",
            "RevisedSessionTimeout",
            DataTypeId::Duration,
            self.revised_session_timeout,
            address_space,
        );
        Ok(node_id)
    }
}

audit_session_event_impl!(AuditCreateSessionEventType, base);

impl AuditCreateSessionEventType {
    pub fn new<R>(node_id: R, time: DateTime) -> Self
    where
        R: Into<NodeId>,
    {
        let event_type_id = ObjectTypeId::AuditCreateSessionEventType;
        Self {
            base: AuditSessionEventType::new(
                node_id,
                event_type_id,
                "AuditCreateSessionEventType",
                "AuditCreateSessionEventType",
                time,
            ),
            secure_channel_id: UAString::null(),
            client_certificate: ByteString::null(),
            client_certificate_thumbprint: UAString::null(),
            revised_session_timeout: 0.0,
        }
    }

    pub fn secure_channel_id<T>(mut self, secure_channel_id: T) -> Self
    where
        T: Into<UAString>,
    {
        self.secure_channel_id = secure_channel_id.into();
        self
    }

    pub fn client_certificate(mut self, client_certificate: &X509) -> Self {
        self.client_certificate = client_certificate.as_byte_string();
        self.client_certificate_thumbprint = client_certificate.thumbprint().as_hex_string().into();
        self
    }

    pub fn revised_session_timeout(mut self, revised_session_timeout: Duration) -> Self {
        self.revised_session_timeout = revised_session_timeout;
        self
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuditActivateSessionEventType {
    base: AuditSessionEventType,
    client_software_certificates: Vec<SignedSoftwareCertificate>,
    user_identity_token: UserIdentityToken,
    secure_channel_id: UAString,
}

impl AuditEvent for AuditActivateSessionEventType {
    fn event_type_id() -> NodeId {
        ObjectTypeId::AuditActivateSessionEventType.into()
    }

    fn log_message(&self) -> String {
        self.base.log_message()
    }
}

impl Event for AuditActivateSessionEventType {
    type Err = ();

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn raise(&mut self, address_space: &mut AddressSpace) -> Result<NodeId, Self::Err> {
        let node_id = self.base.raise(address_space)?;
        let ns = node_id.namespace;
        // Client software certificates is an array of extension objects (extension object i=344)
        let client_software_certificates = self
            .client_software_certificates
            .iter()
            .map(|c| {
                Variant::from(ExtensionObject::from_encodable(
                    ObjectId::SignedSoftwareCertificate_Encoding_DefaultBinary,
                    c,
                ))
            })
            .collect::<Vec<_>>();
        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "ClientSoftwareCertificates",
            "ClientSoftwareCertificates",
            DataTypeId::SignedSoftwareCertificate,
            (VariantTypeId::ExtensionObject, client_software_certificates),
            address_space,
        );

        // User identity token (extension object i=316)
        let user_identity_token = ExtensionObject::from_encodable(
            ObjectId::UserIdentityToken_Encoding_DefaultBinary,
            &self.user_identity_token,
        );
        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "UserIdentityToken",
            "UserIdentityToken",
            DataTypeId::UserIdentityToken,
            user_identity_token,
            address_space,
        );

        self.add_property(
            &node_id,
            NodeId::next_numeric(ns),
            "SecureChannelId",
            "SecureChannelId",
            DataTypeId::String,
            self.secure_channel_id.clone(),
            address_space,
        );
        Ok(node_id)
    }
}

audit_session_event_impl!(AuditActivateSessionEventType, base);

impl AuditActivateSessionEventType {
    pub fn new<R>(node_id: R, time: DateTime) -> Self
    where
        R: Into<NodeId>,
    {
        let event_type_id = ObjectTypeId::AuditCreateSessionEventType;
        Self {
            base: AuditSessionEventType::new(
                node_id,
                event_type_id,
                "AuditCreateSessionEventType",
                "AuditCreateSessionEventType",
                time,
            ),
            client_software_certificates: Vec::new(),
            user_identity_token: UserIdentityToken {
                policy_id: UAString::null(),
            },
            secure_channel_id: UAString::null(),
        }
    }

    pub fn client_software_certificates(
        mut self,
        client_software_certificates: Vec<SignedSoftwareCertificate>,
    ) -> Self {
        self.client_software_certificates = client_software_certificates;
        self
    }

    pub fn user_identity_token(mut self, user_identity_token: UserIdentityToken) -> Self {
        self.user_identity_token = user_identity_token;
        self
    }

    pub fn secure_channel_id<T>(mut self, secure_channel_id: T) -> Self
    where
        T: Into<UAString>,
    {
        self.secure_channel_id = secure_channel_id.into();
        self
    }
}
