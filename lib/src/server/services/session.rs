// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::{Arc, RwLock};

use crate::core::comms::secure_channel::SecureChannel;
use crate::core::supported_message::SupportedMessage;
use crate::crypto::{self as crypto, random, CertificateStore, SecurityPolicy};
use crate::types::{status_code::StatusCode, *};

use crate::server::{
    address_space::address_space::AddressSpace,
    constants,
    identity_token::IdentityToken,
    services::{audit, Service},
    session::{Session, SessionManager},
    state::ServerState,
};

/// The session service. Allows the client to create, activate and close an authenticated session with the server.
pub(crate) struct SessionService;

impl Service for SessionService {
    fn name(&self) -> String {
        String::from("SessionService")
    }
}

impl SessionService {
    pub fn new() -> SessionService {
        SessionService {}
    }

    pub fn create_session(
        &self,
        secure_channel: Arc<RwLock<SecureChannel>>,
        certificate_store: Arc<RwLock<CertificateStore>>,
        server_state: Arc<RwLock<ServerState>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &CreateSessionRequest,
    ) -> (Option<Session>, SupportedMessage) {
        let mut session = Session::new(server_state.clone());
        let server_state = trace_write_lock!(server_state);

        debug!("Create session request {:?}", request);

        let endpoints = server_state.new_endpoint_descriptions(request.endpoint_url.as_ref());

        // Check the args
        let service_result = {
            // Validate the endpoint url
            if request.endpoint_url.is_null() {
                error!("Create session was passed an null endpoint url");
                StatusCode::BadTcpEndpointUrlInvalid
            } else {
                // TODO request.endpoint_url should match hostname of server application certificate
                // Find matching end points for this url
                if endpoints.is_none() {
                    error!("Create session cannot find matching endpoints");
                    StatusCode::BadTcpEndpointUrlInvalid
                } else {
                    StatusCode::Good
                }
            }
        };
        if service_result.is_bad() {
            // Rejected
            let mut diagnostics = trace_write_lock!(server_state.diagnostics);
            diagnostics.on_rejected_session();
            (
                None,
                self.service_fault(&request.request_header, service_result),
            )
        } else {
            let endpoints = endpoints.unwrap();

            // Extract the client certificate if one is supplied
            let client_certificate =
                crypto::X509::from_byte_string(&request.client_certificate).ok();

            // Check the client's certificate for validity and acceptance
            let security_policy = {
                let secure_channel = trace_read_lock!(secure_channel);
                secure_channel.security_policy()
            };
            let service_result = if security_policy != SecurityPolicy::None {
                let certificate_store = trace_read_lock!(certificate_store);
                let result = if let Some(ref client_certificate) = client_certificate {
                    certificate_store.validate_or_reject_application_instance_cert(
                        client_certificate,
                        security_policy,
                        None,
                        None,
                    )
                } else {
                    warn!("Certificate supplied by client is invalid");
                    StatusCode::BadCertificateInvalid
                };
                if result.is_bad() {
                    // Log an error
                    audit::log_certificate_error(
                        &server_state,
                        address_space.clone(),
                        result,
                        &request.request_header,
                    );

                    // Rejected for security reasons
                    let mut diagnostics = trace_write_lock!(server_state.diagnostics);
                    diagnostics.on_rejected_security_session();
                }
                result
            } else {
                StatusCode::Good
            };

            let secure_channel = trace_read_lock!(secure_channel);
            if service_result.is_bad() {
                audit::log_create_session(
                    &server_state,
                    &secure_channel,
                    &session,
                    address_space,
                    false,
                    0f64,
                    request,
                );
                (
                    None,
                    self.service_fault(&request.request_header, service_result),
                )
            } else {
                let session_timeout =
                    if request.requested_session_timeout > constants::MAX_SESSION_TIMEOUT {
                        constants::MAX_SESSION_TIMEOUT
                    } else {
                        request.requested_session_timeout
                    };

                let max_request_message_size = constants::MAX_REQUEST_MESSAGE_SIZE;

                // Calculate a signature (assuming there is a pkey)
                let server_signature = if let Some(ref pkey) = server_state.server_pkey {
                    crypto::create_signature_data(pkey, security_policy, &request.client_certificate, &request.client_nonce)
                        .unwrap_or_else(|err| {
                            error!("Cannot create signature data from private key, check log and error {:?}", err);
                            SignatureData::null()
                        })
                } else {
                    SignatureData::null()
                };
                let authentication_token = NodeId::new(0, random::byte_string(32));
                let server_nonce = security_policy.random_nonce();
                let server_certificate = server_state.server_certificate_as_byte_string();
                let server_endpoints = Some(endpoints);

                session.set_authentication_token(authentication_token.clone());
                session.set_session_timeout(session_timeout);
                session.set_max_request_message_size(max_request_message_size);
                session.set_max_response_message_size(request.max_response_message_size);
                session.set_endpoint_url(request.endpoint_url.clone());
                session.set_security_policy_uri(security_policy.to_uri());
                session.set_user_identity(IdentityToken::None);
                session.set_client_certificate(client_certificate);
                session.set_session_nonce(server_nonce.clone());
                session.set_session_name(request.session_name.clone());

                audit::log_create_session(
                    &server_state,
                    &secure_channel,
                    &session,
                    address_space.clone(),
                    true,
                    session_timeout,
                    request,
                );

                // Create a session id in the address space
                session.register_session(address_space);

                let response = CreateSessionResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    session_id: session.session_id().clone(),
                    authentication_token,
                    revised_session_timeout: session_timeout,
                    server_nonce,
                    server_certificate,
                    server_endpoints,
                    server_software_certificates: None,
                    server_signature,
                    max_request_message_size,
                }
                .into();

                (Some(session), response)
            }
        }
    }

    pub fn activate_session(
        &self,
        secure_channel: Arc<RwLock<SecureChannel>>,
        server_state: Arc<RwLock<ServerState>>,
        session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &ActivateSessionRequest,
    ) -> SupportedMessage {
        let server_state = trace_write_lock!(server_state);
        let mut session = trace_write_lock!(session);
        let endpoint_url = session.endpoint_url().as_ref();

        let (security_policy, security_mode) = {
            let secure_channel = trace_read_lock!(secure_channel);
            (
                secure_channel.security_policy(),
                secure_channel.security_mode(),
            )
        };

        let server_nonce = security_policy.random_nonce();
        let mut service_result =
            if !server_state.endpoint_exists(endpoint_url, security_policy, security_mode) {
                // Need an endpoint
                error!(
                    "Endpoint does not exist for requested url & mode {}, {:?} / {:?}",
                    endpoint_url, security_policy, security_mode
                );
                StatusCode::BadTcpEndpointUrlInvalid
            } else if security_policy != SecurityPolicy::None {
                // Crypto see 5.6.3.1 verify the caller is the same caller as create_session by validating
                // signature supplied by the client during the create.
                Self::verify_client_signature(
                    security_policy,
                    &server_state,
                    &session,
                    &request.client_signature,
                )
            } else {
                // No cert checks for no security
                StatusCode::Good
            };

        if service_result.is_good() {
            if let Err(err) = server_state.authenticate_endpoint(
                request,
                endpoint_url,
                security_policy,
                security_mode,
                &request.user_identity_token,
                session.session_nonce(),
            ) {
                service_result = err;
            }
        }

        // Authenticate the user identity token
        if service_result.is_good() {
            session.set_activated(true);
            session.set_session_nonce(server_nonce);
            session.set_user_identity(IdentityToken::new(
                &request.user_identity_token,
                &server_state.decoding_options(),
            ));
            session.set_locale_ids(request.locale_ids.clone());

            let diagnostic_infos = None;

            {
                let secure_channel = trace_read_lock!(secure_channel);
                audit::log_activate_session(
                    &secure_channel,
                    &server_state,
                    &session,
                    address_space,
                    true,
                    request,
                );
            }

            ActivateSessionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                server_nonce: session.session_nonce().clone(),
                results: None,
                diagnostic_infos,
            }
            .into()
        } else {
            session.set_activated(false);
            self.service_fault(&request.request_header, service_result)
        }
    }

    pub fn close_session(
        &self,
        session_manager: Arc<RwLock<SessionManager>>,
        server_state: Arc<RwLock<ServerState>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &CloseSessionRequest,
    ) -> SupportedMessage {
        let server_state = trace_write_lock!(server_state);
        let session = {
            let session_manager = trace_read_lock!(session_manager);
            session_manager.find_session_by_token(&request.request_header.authentication_token)
        };
        if let Some(session) = session {
            {
                let mut session = trace_write_lock!(session);
                session.set_authentication_token(NodeId::null());
                session.set_user_identity(IdentityToken::None);
                session.set_activated(false);
                audit::log_close_session(&server_state, &session, address_space, true, request);
            }

            {
                let mut session_manager = trace_write_lock!(session_manager);
                session_manager.deregister_session(session);
            }

            CloseSessionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
            }
            .into()
        } else {
            self.service_fault(&request.request_header, StatusCode::BadSessionIdInvalid)
        }
    }

    pub fn cancel(
        &self,
        _server_state: Arc<RwLock<ServerState>>,
        _session: Arc<RwLock<Session>>,
        request: &CancelRequest,
    ) -> SupportedMessage {
        // This service call currently does nothing
        CancelResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            cancel_count: 0,
        }
        .into()
    }

    /// Verifies that the supplied client signature was produced by the session's client certificate
    /// from the server's certificate and nonce.
    fn verify_client_signature(
        security_policy: SecurityPolicy,
        server_state: &ServerState,
        session: &Session,
        client_signature: &SignatureData,
    ) -> StatusCode {
        if let Some(ref client_certificate) = session.client_certificate() {
            if let Some(ref server_certificate) = server_state.server_certificate {
                crypto::verify_signature_data(
                    client_signature,
                    security_policy,
                    client_certificate,
                    server_certificate,
                    session.session_nonce().as_ref(),
                )
            } else {
                error!("Client signature verification failed, server has no server certificate");
                StatusCode::BadUnexpectedError
            }
        } else {
            error!("Client signature verification failed, session has no client certificate");
            StatusCode::BadUnexpectedError
        }
    }
}
