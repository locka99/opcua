// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::Arc;

use crate::core::supported_message::SupportedMessage;
use crate::sync::*;
use crate::types::{status_code::StatusCode, *};

use crate::server::{
    address_space::AddressSpace, services::Service, session::SessionManager, state::ServerState,
};

/// The method service. Allows a client to call a method on the server.
pub(crate) struct MethodService;

impl Service for MethodService {
    fn name(&self) -> String {
        String::from("MethodService")
    }
}

impl MethodService {
    pub fn new() -> MethodService {
        MethodService {}
    }

    pub fn call(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        session_id: &NodeId,
        session_manager: Arc<RwLock<SessionManager>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request: &CallRequest,
    ) -> SupportedMessage {
        if let Some(ref calls) = request.methods_to_call {
            let server_state = trace_read_lock!(server_state);
            if calls.len() <= server_state.operational_limits.max_nodes_per_method_call {
                let mut address_space = trace_write_lock!(address_space);

                let results: Vec<CallMethodResult> = calls
                    .iter()
                    .map(|request| {
                        trace!(
                            "Calling to {:?} on {:?}",
                            request.method_id,
                            request.object_id
                        );

                        // Note: Method invocations that modify the address space, write a value, or modify the
                        // state of the system (acknowledge, batch sequencing or other system changes) must
                        // generate an AuditUpdateMethodEventType or a subtype of it.

                        // Call the method via whatever is registered in the address space
                        match address_space.call_method(
                            &server_state,
                            session_id,
                            session_manager.clone(),
                            request,
                        ) {
                            Ok(response) => response,
                            Err(status_code) => {
                                // Call didn't work for some reason
                                error!(
                                    "Call to {:?} on {:?} failed with status code {}",
                                    request.method_id, request.object_id, status_code
                                );
                                CallMethodResult {
                                    status_code,
                                    input_argument_results: None,
                                    input_argument_diagnostic_infos: None,
                                    output_arguments: None,
                                }
                            }
                        }
                    })
                    .collect();
                // Produce response
                let response = CallResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    results: Some(results),
                    diagnostic_infos: None,
                };
                response.into()
            } else {
                error!("Call request, too many calls {}", calls.len());
                self.service_fault(&request.request_header, StatusCode::BadTooManyOperations)
            }
        } else {
            warn!("Call has nothing to do");
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        }
    }
}
