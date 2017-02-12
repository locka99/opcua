use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use types::*;
use server::ServerState;

pub struct SessionService {}

impl SessionService {
    pub fn new() -> SessionService {
        SessionService {}
    }

    pub fn create_session(&self, server_state: &mut ServerState, _: &mut SessionState, request: &CreateSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        // TODO validate client certificate

        // TODO these need to be stored in the session
        let session_id = NodeId::new_numeric(1, 1234);
        let authentication_token = NodeId::new_byte_string(0, ByteString::random(32));
        let session_timeout = 50000f64;
        let max_request_message_size = 32768;

        // TODO crypto
        let server_nonce = ByteString::random(32);
        let server_certificate = server_state.server_certificate.clone();
        let server_software_certificates = None;
        let server_signature = SignatureData {
            algorithm: UAString::null(),
            signature: ByteString::null(),
        };

        let response = CreateSessionResponse {
            response_header: ResponseHeader::new_good(&DateTime::now(), &request.request_header),
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

    pub fn close_session(&self, _: &mut ServerState, _: &mut SessionState, request: &CloseSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let response = CloseSessionResponse {
            response_header: ResponseHeader::new_good(&DateTime::now(), &request.request_header),
        };
        Ok(SupportedMessage::CloseSessionResponse(response))
    }

    pub fn activate_session(&self, _: &mut ServerState, _: &mut SessionState, request: &ActivateSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {

        let mut status_code = &GOOD;

        // Only anonymous user identity tokens at this time
        if request.user_identity_token.node_id != ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary.as_node_id() {
            status_code = &BAD_IDENTITY_TOKEN_REJECTED;
        }


        let server_nonce = ByteString::random(32);
        let response = ActivateSessionResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, status_code),
            server_nonce: server_nonce,
            results: None,
            diagnostic_infos: None,
        };
        Ok(SupportedMessage::ActivateSessionResponse(response))
    }
}