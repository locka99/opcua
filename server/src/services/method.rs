use std::result::Result;

use opcua_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::service_types::*;

use address_space::address_space::AddressSpace;
use services::Service;
use session::Session;
use state::ServerState;
use constants;

pub struct MethodService {}

impl Service for MethodService {}

impl MethodService {
    pub fn new() -> MethodService {
        MethodService {}
    }

    pub fn call(&self, address_space: &AddressSpace, server_state: &ServerState, session: &Session, request: CallRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(calls) = request.methods_to_call {
            if calls.len() >= constants::MAX_METHOD_CALLS {
                return Ok(self.service_fault(&request.request_header, StatusCode::BadTooManyOperations));
            } else {
                let results: Vec<CallMethodResult> = calls.iter().map(|request| {
                    address_space.call_method(server_state, session, request)
                }).collect();
                // Produce response
                let response = CallResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos: None,
                };
                Ok(response.into())
            }
        } else {
            warn!("Call has nothing to do");
            return Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo));
        }
    }
}
