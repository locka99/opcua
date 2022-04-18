// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::Arc;

use crate::sync::*;
use crate::types::{status_code::StatusCode, *};

use crate::server::prelude::SecureChannel;
use crate::server::{
    address_space::address_space::AddressSpace,
    events::audit::{certificate_events::*, session_events::*},
    session::Session,
    state::ServerState,
};

fn next_node_id(address_space: Arc<RwLock<AddressSpace>>) -> NodeId {
    let audit_namespace = {
        let address_space = trace_read_lock!(address_space);
        address_space.audit_namespace()
    };
    NodeId::next_numeric(audit_namespace)
}

pub fn log_create_session(
    server_state: &ServerState,
    secure_channel: &SecureChannel,
    session: &Session,
    address_space: Arc<RwLock<AddressSpace>>,
    status: bool,
    revised_session_timeout: Duration,
    request: &CreateSessionRequest,
) {
    let node_id = next_node_id(address_space);
    let now = DateTime::now();

    // Raise an event
    let event = AuditCreateSessionEventType::new(node_id, now)
        .status(status)
        .client_audit_entry_id(request.request_header.audit_entry_id.clone());

    let event = if status {
        let session_id = session.session_id().clone();
        let secure_channel_id = format!("{}", secure_channel.secure_channel_id());

        let event = event
            .session_id(session_id)
            .secure_channel_id(secure_channel_id)
            .revised_session_timeout(revised_session_timeout);

        // Client certificate info
        if let Some(ref client_certificate) = session.client_certificate() {
            event.client_certificate(client_certificate)
        } else {
            event
        }
    } else {
        event
    };

    let _ = server_state.raise_and_log(event);
}

pub fn log_activate_session(
    secure_channel: &SecureChannel,
    server_state: &ServerState,
    session: &Session,
    address_space: Arc<RwLock<AddressSpace>>,
    status: bool,
    request: &ActivateSessionRequest,
) {
    let node_id = next_node_id(address_space);
    let now = DateTime::now();

    let session_id = session.session_id().clone();
    let secure_channel_id = format!("{}", secure_channel.secure_channel_id());
    let event = AuditActivateSessionEventType::new(node_id, now)
        .status(status)
        .session_id(session_id)
        .client_audit_entry_id(request.request_header.audit_entry_id.clone())
        .secure_channel_id(secure_channel_id);

    let event = if status {
        // Client software certificates
        let event =
            if let Some(ref client_software_certificates) = request.client_software_certificates {
                event.client_software_certificates(client_software_certificates.clone())
            } else {
                event
            };

        // TODO user identity token - should we serialize the entire token in an audit log, or just the policy uri?
        //  from a security perspective, logging credentials is bad.

        event
    } else {
        event
    };

    let _ = server_state.raise_and_log(event);
}

pub fn log_close_session(
    server_state: &ServerState,
    session: &Session,
    address_space: Arc<RwLock<AddressSpace>>,
    status: bool,
    request: &CloseSessionRequest,
) {
    let node_id = next_node_id(address_space);
    let now = DateTime::now();

    let session_id = session.session_id().clone();
    let event = AuditSessionEventType::new_close_session(
        node_id,
        now,
        AuditCloseSessionReason::CloseSession,
    )
    .status(status)
    .client_user_id(session.client_user_id())
    .client_audit_entry_id(request.request_header.audit_entry_id.clone())
    .session_id(session_id);

    let _ = server_state.raise_and_log(event);
}

pub fn log_certificate_error(
    server_state: &ServerState,
    address_space: Arc<RwLock<AddressSpace>>,
    status_code: StatusCode,
    request_header: &RequestHeader,
) {
    let node_id = next_node_id(address_space);
    let now = DateTime::now();

    match status_code.status() {
        StatusCode::BadCertificateTimeInvalid => {
            let event = AuditCertificateExpiredEventType::new(node_id, now)
                .client_audit_entry_id(request_header.audit_entry_id.clone());
            let _ = server_state.raise_and_log(event);
        }
        _ => {
            // TODO client_id
            let event = AuditCertificateInvalidEventType::new(node_id, now)
                .client_audit_entry_id(request_header.audit_entry_id.clone());
            let _ = server_state.raise_and_log(event);
        }
    };
}
