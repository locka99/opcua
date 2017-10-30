use std::result::Result;

use opcua_types::*;

use opcua_core::crypto;
use opcua_core::crypto::SecurityPolicy;

use constants;
use server::ServerState;
use session::Session;
use services::Service;

pub struct SessionService {}

impl Service for SessionService {}

impl SessionService {
    pub fn new() -> SessionService {
        SessionService {}
    }

    pub fn create_session(&self, server_state: &mut ServerState, session: &mut Session, request: CreateSessionRequest) -> Result<SupportedMessage, StatusCode> {
        debug!("Create session request {:?}", request);

        // Validate the endpoint url
        if request.endpoint_url.is_null() {
            return Ok(self.service_fault(&request.request_header, BAD_TCP_ENDPOINT_URL_INVALID));
        }

        // TODO request.endpoint_url should match hostname of server application certificate

        // Find matching end points for this url
        let endpoints = server_state.new_endpoint_descriptions(request.endpoint_url.as_ref());
        if endpoints.is_none() {
            return Ok(self.service_fault(&request.request_header, BAD_TCP_ENDPOINT_URL_INVALID));
        }
        let endpoints = endpoints.unwrap();

        // Check the client's certificate for validity and acceptance
        let security_policy = session.secure_channel.security_policy;
        let service_result = if security_policy != SecurityPolicy::None {
            if let Ok(client_certificate) = crypto::X509::from_byte_string(&request.client_certificate) {
                let certificate_store = server_state.certificate_store.lock().unwrap();
                certificate_store.validate_or_reject_application_instance_cert(&client_certificate)
            } else {
                warn!("Certificate supplied by client is invalid");
                BAD_CERTIFICATE_INVALID
            }
        } else {
            GOOD
        };
        let response = if service_result.is_bad() {
            self.service_fault(&request.request_header, service_result)
        } else {
            let session_id = session.next_session_id();
            let authentication_token = NodeId::new(0, ByteString::random(32));
            let session_timeout = constants::SESSION_TIMEOUT;
            let max_request_message_size = constants::MAX_REQUEST_MESSAGE_SIZE;

            // Calculate a signature (assuming there is a pkey)
            let server_signature = if server_state.server_pkey.is_some() {
                let pkey = server_state.server_pkey.as_ref().unwrap();
                crypto::create_signature_data(pkey, security_policy, &request.client_certificate, &request.client_nonce).unwrap()
            } else {
                SignatureData::null()
            };

            // Crypto
            let server_nonce = ByteString::random(32);
            let server_certificate = server_state.server_certificate_as_byte_string();
            let server_endpoints = Some(endpoints);

            session.session_id = session_id.clone();
            session.authentication_token = authentication_token.clone();
            session.session_timeout = session_timeout;
            session.max_request_message_size = max_request_message_size;
            session.max_response_message_size = request.max_response_message_size;
            session.endpoint_url = request.endpoint_url.clone();
            session.security_policy_uri = security_policy.to_uri().to_string();
            session.user_identity = None;
            session.client_certificate = request.client_certificate.clone();
            session.session_nonce = server_nonce.clone();

            SupportedMessage::CreateSessionResponse(CreateSessionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                session_id,
                authentication_token,
                revised_session_timeout: session_timeout,
                server_nonce,
                server_certificate,
                server_endpoints,
                server_software_certificates: None,
                server_signature,
                max_request_message_size,
            })
        };
        Ok(response)
    }

    pub fn activate_session(&self, server_state: &mut ServerState, session: &mut Session, request: ActivateSessionRequest) -> Result<SupportedMessage, StatusCode> {
        let server_nonce = ByteString::random(32);

        let endpoint_url = session.endpoint_url.as_ref();
        let security_policy = session.secure_channel.security_policy;
        let security_mode = session.secure_channel.security_mode;

        let mut service_result = if !server_state.endpoint_exists(endpoint_url, security_policy, security_mode) {
            // Need an endpoint
            BAD_TCP_ENDPOINT_URL_INVALID
        } else if security_policy != SecurityPolicy::None {
            // Crypto see 5.6.3.1 verify the caller is the same caller as create_session by validating
            // signature supplied by client
            let mut service_result = BAD_UNEXPECTED_ERROR;
            if server_state.server_certificate.is_some() {
                if let Ok(client_cert) = crypto::X509::from_byte_string(&session.client_certificate) {
                    let server_certificate = server_state.server_certificate.as_ref().unwrap().as_byte_string();
                    service_result = crypto::verify_signature(&client_cert, &request.client_signature, &server_certificate, &server_nonce);
                }
            }
            service_result
        } else {
            // No cert checks for no security
            GOOD
        };

        // Authenticate the user identity token
        if service_result.is_good() {
            service_result = server_state.authenticate_endpoint(endpoint_url, security_policy, security_mode, &request.user_identity_token);
        }

        let response = if service_result.is_good() {
            session.activated = true;
            session.session_nonce = server_nonce;
            let diagnostic_infos = None;
            SupportedMessage::ActivateSessionResponse(ActivateSessionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                server_nonce: session.session_nonce.clone(),
                results: None,
                diagnostic_infos,
            })
        } else {
            self.service_fault(&request.request_header, service_result)
        };
        Ok(response)
    }

    pub fn close_session(&self, _: &mut ServerState, session: &mut Session, request: CloseSessionRequest) -> Result<SupportedMessage, StatusCode> {
        session.authentication_token = NodeId::null();
        session.user_identity = None;
        session.activated = false;
        let response = CloseSessionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
        };
        Ok(SupportedMessage::CloseSessionResponse(response))
    }
}