use std::result::Result;

use opcua_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::service_types::*;

use services::Service;
use session::Session;

pub struct MethodService {}

impl Service for MethodService {}

impl MethodService {
    pub fn new() -> MethodService {
        MethodService {}
    }

    pub fn call(&self, session: &mut Session, request: CallRequest) -> Result<SupportedMessage, StatusCode> {
        if let Some(calls) = request.methods_to_call {
            // TODO for each call
            {
                // get the object id
                // BadNodeIdUnknown

                // look for the corresponding method id
                // BadMethodInvalid
                // BadNodeIdUnknown

                // look up method implementation in some kind of table

                // invoke the method

                // produce a call result
            }
            // Produce response

            Err(StatusCode::BadNotImplemented)
        } else {
            warn!("Call has nothing to do");
            return Ok(self.service_fault(&request.request_header, StatusCode::BadNothingToDo));
        }
    }
}
