use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use constants;
use server::{Endpoint, ServerState};
use session::{Session};

pub struct SessionService {}

impl SessionService {
    pub fn new() -> SessionService {
        SessionService {}
    }

    pub fn create_session(&self, server_state: &mut ServerState, session: &mut Session, request: CreateSessionRequest) -> Result<SupportedMessage, StatusCode> {
        // TODO crypto validate client certificate

        // Validate the endpoint url
        if request.endpoint_url.is_null() {
            return Err(BAD_TCP_ENDPOINT_URL_INVALID);
        } else {
            let endpoint = server_state.find_endpoint(request.endpoint_url.to_str());
            if endpoint.is_none() {
                return Err(BAD_TCP_ENDPOINT_URL_INVALID);
            }
        }

        let service_status = GOOD;

        let session_id = session.next_session_id();
        let authentication_token = NodeId::new_byte_string(0, ByteString::random(32));
        let session_timeout = constants::SESSION_TIMEOUT;
        let max_request_message_size = constants::MAX_REQUEST_MESSAGE_SIZE;

        // TODO crypto
        let server_nonce = ByteString::random(32);
        let server_certificate = server_state.server_certificate.clone();
        let server_software_certificates = None;
        let server_signature = SignatureData {
            algorithm: UAString::null(),
            signature: ByteString::null(),
        };

        session.session_id = session_id.clone();
        session.authentication_token = authentication_token.clone();
        session.session_timeout = session_timeout;
        session.max_request_message_size = max_request_message_size;
        session.max_response_message_size = request.max_response_message_size;
        session.endpoint_url = request.endpoint_url.clone();
        session.user_identity = None;

        let response = CreateSessionResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            session_id: session_id,
            authentication_token: authentication_token,
            revised_session_timeout: session_timeout,
            server_nonce: server_nonce,
            server_certificate: server_certificate,
            server_endpoints: Some(server_state.endpoints()),
            server_software_certificates: server_software_certificates,
            server_signature: server_signature,
            max_request_message_size: max_request_message_size,
        };

        Ok(SupportedMessage::CreateSessionResponse(response))
    }

    pub fn activate_session(&self, server_state: &mut ServerState, session: &mut Session, request: ActivateSessionRequest) -> Result<SupportedMessage, StatusCode> {
        // TODO crypto see 5.6.3.1 verify the caller is the same caller as create_session by validating
        // signature supplied by client

        // TODO crypto secure channel verification

        let endpoint = SessionService::get_session_endpoint(server_state, session);
        if endpoint.is_none() {
            return Err(BAD_TCP_ENDPOINT_URL_INVALID);
        }
        let endpoint = endpoint.unwrap();
        endpoint.validate_identity_token(&request.user_identity_token);

        let service_status = GOOD;
        let server_nonce = ByteString::random(32);

        session.activated = true;

        let response = ActivateSessionResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            server_nonce: server_nonce,
            results: None,
            diagnostic_infos: None,
        };

        Ok(SupportedMessage::ActivateSessionResponse(response))
    }

    pub fn close_session(&self, _: &mut ServerState, session: &mut Session, request: CloseSessionRequest) -> Result<SupportedMessage, StatusCode> {
        let service_status = GOOD;
        session.authentication_token = NodeId::null();
        session.user_identity = None;
        session.activated = false;
        let response = CloseSessionResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
        };
        Ok(SupportedMessage::CloseSessionResponse(response))
    }

    fn get_session_endpoint(server_state: &ServerState, session: &Session) -> Option<Endpoint> {
        // Get security from endpoint url
        if session.endpoint_url.is_null() {
            None
        } else {
            server_state.find_endpoint(session.endpoint_url.to_str())
        }
    }
}