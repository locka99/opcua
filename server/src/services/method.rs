use std::result::Result;

use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::service_types::*;

use crate::{
    address_space::AddressSpace,
    services::Service,
    session::Session,
    state::ServerState,
};

/// The method service. Allows a client to call a method on the server.
pub(crate) struct MethodService;

impl Service for MethodService {}

impl MethodService {
    pub fn new() -> MethodService {
        MethodService {}
    }

    pub fn call(&self, address_space: &AddressSpace, server_state: &ServerState, session: &mut Session, request: &CallRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref calls) = request.methods_to_call {
            if calls.len() >= server_state.max_method_calls() {
                Ok(self.service_fault(&request.request_header, StatusCode::BadTooManyOperations))
            } else {
                let results: Vec<CallMethodResult> = calls.iter().map(|request| {
                    trace!("Calling to {:?} on {:?}", request.method_id, request.object_id);
                    // Call the method via whatever is registered in the address space
                    match address_space.call_method(server_state, session, request) {
                        Ok(response) => response,
                        Err(status_code) => {
                            // Call didn't work for some reason
                            error!("Call to {:?} on {:?} failed with status code {}", request.method_id, request.object_id, status_code);
                            CallMethodResult {
                                status_code,
                                input_argument_results: None,
                                input_argument_diagnostic_infos: None,
                                output_arguments: None,
                            }
                        }
                    }
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
            Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo))
        }
    }
}
