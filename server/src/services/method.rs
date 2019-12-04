use std::{
    result::Result,
    sync::{Arc, RwLock},
};

use opcua_types::*;
use opcua_types::status_code::StatusCode;

use crate::{
    address_space::AddressSpace,
    services::Service,
    session::Session,
    state::ServerState,
};

/// The method service. Allows a client to call a method on the server.
pub(crate) struct MethodService;

impl Service for MethodService {
    fn name(&self) -> String { String::from("MethodService") }
}

impl MethodService {
    pub fn new() -> MethodService {
        MethodService {}
    }

    pub fn call(&self, server_state: Arc<RwLock<ServerState>>, session: Arc<RwLock<Session>>, address_space: Arc<RwLock<AddressSpace>>, request: &CallRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(ref calls) = request.methods_to_call {
            let server_state = trace_read_lock_unwrap!(server_state);
            if calls.len() >= server_state.max_method_calls() {
                Ok(self.service_fault(&request.request_header, StatusCode::BadTooManyOperations))
            } else {
                let mut session = trace_write_lock_unwrap!(session);
                let mut address_space = trace_write_lock_unwrap!(address_space);

                let results: Vec<CallMethodResult> = calls.iter().map(|request| {
                    trace!("Calling to {:?} on {:?}", request.method_id, request.object_id);
                    // Call the method via whatever is registered in the address space
                    match address_space.call_method(&server_state, &mut session, request) {
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
