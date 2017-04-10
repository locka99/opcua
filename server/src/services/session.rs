use std::result::Result;
use std::io::{Cursor};

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use constants;
use server::ServerState;
use session::{SessionState, SessionInfo};

pub struct SessionService {}

impl SessionService {
    pub fn new() -> SessionService {
        SessionService {}
    }

    pub fn create_session(&self, server_state: &mut ServerState, session_state: &mut SessionState, request: CreateSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let service_status = &GOOD;

        // TODO validate client certificate

        // TODO validate endpoint url

        let session_id = session_state.next_session_id();
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

        if service_status.is_good() {
            let session_info = SessionInfo {
                session_id: session_id.clone(),
                authentication_token: authentication_token.clone(),
                session_timeout: session_timeout,
                max_request_message_size: max_request_message_size,
                max_response_message_size: request.max_response_message_size,
                endpoint_url: request.endpoint_url.clone()
            };
            session_state.session_info = Some(session_info);
        }

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

    pub fn close_session(&self, _: &mut ServerState, _: &mut SessionState, request: CloseSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let service_status = &GOOD;
        let response = CloseSessionResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
        };
        Ok(SupportedMessage::CloseSessionResponse(response))
    }

    pub fn activate_session(&self, server_state: &mut ServerState, session_state: &mut SessionState, request: ActivateSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        // TODO get security from endpoint url
        let session_info = session_state.session_info.as_ref().unwrap();

        let identity_token_id = request.user_identity_token.node_id.clone();
        let service_status = if identity_token_id == ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary.as_node_id() {
            // TODO ensure session allows anonymous id
            &GOOD
        } else if identity_token_id == ObjectId::UserNameIdentityToken_Encoding_DefaultBinary.as_node_id() {
            // TODO ensure session allows user id
            let mut result = &BAD_IDENTITY_TOKEN_REJECTED;
            if let ExtensionObjectEncoding::ByteString(ref data) = request.user_identity_token.body {
                if let Some(ref data) = data.value {
                    let mut stream = Cursor::new(data);
                    if let Ok(token) = UserNameIdentityToken::decode(&mut stream) {
                        if server_state.validate_username_identity_token(&token) {
                            result = &GOOD;
                        }
                    }
                }
            }
            result
        } else {
            &BAD_IDENTITY_TOKEN_REJECTED
        };

        let server_nonce = ByteString::random(32);
        let response = ActivateSessionResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            server_nonce: server_nonce,
            results: None,
            diagnostic_infos: None,
        };
        Ok(SupportedMessage::ActivateSessionResponse(response))
    }
}