use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

pub struct SessionService {}

impl SessionService {
    pub fn new() -> SessionService {
        SessionService {}
    }

    pub fn handle_create_sesion_request(&self, request: &CreateSessionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("handle_create_sesion_request {:#?}", request);
        Err(&BAD_UNEXPECTED_ERROR)
    }
}