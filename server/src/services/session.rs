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

    pub fn create_session(&self, _: &mut ServerState, _: &mut SessionState, request: &CreateSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("create_session {:#?}", request);

        // TODO validate client certificate

        // TODO these need to be stored in the session
        let session_id = NodeId::new_numeric(1, 1234);
        let authentication_token = NodeId::new_string(1, "abcdef");
        let session_timeout = 50000f64;
        let max_request_message_size = 32768;

        // TODO crypto
        let server_nonce = ByteString::null();
        let server_certificate = ByteString::null();
        let server_software_certificates = None;
        let server_signature = SignatureData {
            algorithm: UAString::null(),
            signature: ByteString::null(),
        };

        let response = CreateSessionResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
            session_id: session_id,
            authentication_token: authentication_token,
            revised_session_timeout: session_timeout,
            server_nonce: server_nonce,
            server_certificate: server_certificate,
            server_endpoints: None,
            server_software_certificates: server_software_certificates,
            server_signature: server_signature,
            max_request_message_size: max_request_message_size,
        };

        Ok(SupportedMessage::CreateSessionResponse(response))
    }

    pub fn close_session(&self, _: &mut ServerState, _: &mut SessionState, request: &CloseSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("close_session {:#?}", request);
        let response = CloseSessionResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
        };
        Ok(SupportedMessage::CloseSessionResponse(response))
    }

    pub fn activate_session(&self, _: &mut ServerState, _: &mut SessionState, request: &ActivateSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("activate_session {:#?}", request);

        // TODO validate user identity token

        let server_nonce = ByteString::null();

        let response = ActivateSessionResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
            server_nonce: server_nonce,
            results: None,
            diagnostic_infos: None,
        };
        Ok(SupportedMessage::ActivateSessionResponse(response))
    }
}