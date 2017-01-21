use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use server::ServerState;
use tcp_session::SessionState;

pub struct SessionService {}

impl SessionService {
    pub fn new() -> SessionService {
        SessionService {}
    }

    pub fn handle_create_session_request(&self, server_state: &mut ServerState, session_state: &mut SessionState, request: &CreateSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("handle_create_sesion_request {:#?}", request);

        // TODO these need to be stored in the session
        let session_id = NodeId::new_numeric(1, 1234);
        let authentication_token = NodeId::new_string(1, UAString::from_str("abcdef"));
        let session_timeout = 50000f64;
        let max_request_message_size = 32768;
        let now = DateTime::now();

        let response = CreateSessionResponse {
            response_header: ResponseHeader::new(&now, request.request_header.request_handle),
            session_id: session_id,
            authentication_token: authentication_token,
            revised_session_timeout: session_timeout,
            server_nonce: ByteString::null(),
            server_certificate: ByteString::null(),
            server_endpoints: None,
            server_software_certificates: None,
            server_signature: SignatureData {
                algorithm: UAString::null(),
                signature: ByteString::null(),
            },
            max_request_message_size: max_request_message_size,
        };

        Ok(SupportedMessage::CreateSessionResponse(response))
    }

    pub fn handle_close_session_request(&self, server_state: &mut ServerState, session_state: &mut SessionState, request: &CloseSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let now = DateTime::now();
        let response = CloseSessionResponse {
            response_header: ResponseHeader::new(&now, request.request_header.request_handle),
        };
        Ok(SupportedMessage::CloseSessionResponse(response))
    }
}