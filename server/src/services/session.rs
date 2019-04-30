use std::result::Result;

use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::service_types::*;

use opcua_core::crypto;
use opcua_core::crypto::SecurityPolicy;
use opcua_core::crypto::CertificateStore;

use crate::{
    constants,
    state::ServerState,
    session::Session,
    services::Service,
};

/// The session service. Allows the client to create, activate and close an authenticated session with the server.
pub(crate) struct SessionService;

impl Service for SessionService {
    fn name(&self) -> String { String::from("SessionService") }
}

impl SessionService {
    pub fn new() -> SessionService {
        SessionService {}
    }

    pub fn create_session(&self, certificate_store: &CertificateStore, server_state: &mut ServerState, session: &mut Session, request: &CreateSessionRequest) -> Result<SupportedMessage, StatusCode> {
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
            let mut diagnostics = trace_write_lock_unwrap!(server_state.diagnostics);
            diagnostics.on_rejected_session();
            Ok(self.service_fault(&request.request_header, service_result))
        } else {
            let endpoints = endpoints.unwrap();

            // Extract the client certificate if one is supplied
            let client_certificate = crypto::X509::from_byte_string(&request.client_certificate).ok();

            // Check the client's certificate for validity and acceptance
            let security_policy = {
                let secure_channel = trace_read_lock_unwrap!(session.secure_channel);
                secure_channel.security_policy()
            };
            let service_result = if security_policy != SecurityPolicy::None {
                let result = if let Some(ref client_certificate) = client_certificate {
                    certificate_store.validate_or_reject_application_instance_cert(client_certificate, None, None)
                } else {
                    warn!("Certificate supplied by client is invalid");
                    StatusCode::BadCertificateInvalid
                };
                if result.is_bad() {
                    // Rejected for security reasons
                    let mut diagnostics = trace_write_lock_unwrap!(server_state.diagnostics);
                    diagnostics.on_rejected_security_session();
                }
                result
            } else {
                StatusCode::Good
            };

            let response = if service_result.is_bad() {
                self.service_fault(&request.request_header, service_result)
            } else {
                let session_timeout = if request.requested_session_timeout > constants::MAX_SESSION_TIMEOUT {
                    constants::MAX_SESSION_TIMEOUT
                } else {
                    request.requested_session_timeout
                };

                let max_request_message_size = constants::MAX_REQUEST_MESSAGE_SIZE;

                // Calculate a signature (assuming there is a pkey)
                let server_signature = if let Some(ref pkey) = server_state.server_pkey {
                    crypto::create_signature_data(pkey, security_policy, &request.client_certificate, &request.client_nonce)?
                } else {
                    SignatureData::null()
                };
                let authentication_token = NodeId::new(0, ByteString::random(32));
                let server_nonce = security_policy.random_nonce();
                let server_certificate = server_state.server_certificate_as_byte_string();
                let server_endpoints = Some(endpoints);

                session.authentication_token = authentication_token.clone();
                session.session_timeout = session_timeout;
                session.max_request_message_size = max_request_message_size;
                session.max_response_message_size = request.max_response_message_size;
                session.endpoint_url = request.endpoint_url.clone();
                session.security_policy_uri = security_policy.to_uri().to_string();
                session.user_identity = None;
                session.client_certificate = client_certificate;
                session.session_nonce = server_nonce.clone();

                CreateSessionResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    session_id: session.session_id.clone(),
                    authentication_token,
                    revised_session_timeout: session_timeout,
                    server_nonce,
                    server_certificate,
                    server_endpoints,
                    server_software_certificates: None,
                    server_signature,
                    max_request_message_size,
                }.into()
            };
            Ok(response)
        }
    }

    pub fn activate_session(&self, server_state: &mut ServerState, session: &mut Session, request: &ActivateSessionRequest) -> Result<SupportedMessage, StatusCode> {
        let endpoint_url = session.endpoint_url.as_ref();

        let (security_policy, security_mode) = {
            let secure_channel = trace_read_lock_unwrap!(session.secure_channel);
            (secure_channel.security_policy(), secure_channel.security_mode())
        };

        let server_nonce = security_policy.random_nonce();

        let mut service_result = if !server_state.endpoint_exists(endpoint_url, security_policy, security_mode) {
            // Need an endpoint
            error!("Endpoint does not exist for requested url & mode {}, {:?} / {:?}", endpoint_url, security_policy, security_mode);
            StatusCode::BadTcpEndpointUrlInvalid
        } else if security_policy != SecurityPolicy::None {
            // Crypto see 5.6.3.1 verify the caller is the same caller as create_session by validating
            // signature supplied by the client during the create.
            Self::verify_client_signature(server_state, session, &request.client_signature)
        } else {
            // No cert checks for no security
            StatusCode::Good
        };

        if service_result.is_good() {
            if let Err(err) = server_state.authenticate_endpoint(endpoint_url, security_policy, security_mode, &request.user_identity_token, &session.session_nonce) {
                service_result = err;
            }
        }

        // Authenticate the user identity token
        let response = if service_result.is_good() {
            session.activated = true;
            session.session_nonce = server_nonce;
            let diagnostic_infos = None;

            ActivateSessionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                server_nonce: session.session_nonce.clone(),
                results: None,
                diagnostic_infos,
            }.into()
        } else {
            self.service_fault(&request.request_header, service_result)
        };
        Ok(response)
    }

    pub fn close_session(&self, session: &mut Session, request: &CloseSessionRequest) -> Result<SupportedMessage, StatusCode> {
        session.authentication_token = NodeId::null();
        session.user_identity = None;
        session.activated = false;
        let response = CloseSessionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
        };
        Ok(response.into())
    }

    pub fn cancel(&self, _server_state: &mut ServerState, _session: &mut Session, request: &CancelRequest) -> Result<SupportedMessage, StatusCode> {
        // This service call currently does nothing
        let response = CancelResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            cancel_count: 0,
        };
        Ok(response.into())
    }

    /// Verifies that the supplied client signature was produced by the session's client certificate
    /// from the server's certificate and nonce.
    fn verify_client_signature(server_state: &ServerState, session: &Session, client_signature: &SignatureData) -> StatusCode {
        if let Some(ref client_certificate) = session.client_certificate {
            if let Some(ref server_certificate) = server_state.server_certificate {
                let security_policy = {
                    let secure_channel = trace_read_lock_unwrap!(session.secure_channel);
                    secure_channel.security_policy()
                };
                crypto::verify_signature_data(client_signature, security_policy, client_certificate, server_certificate, &session.session_nonce)
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