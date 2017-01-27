use std::result::Result;

use opcua_core::types::*;
use opcua_core::comms::*;

use types::*;
use server::ServerState;

pub struct AttributeService {}

impl AttributeService {
    pub fn new() -> AttributeService {
        AttributeService {}
    }

    pub fn read(&self, server_state: &mut ServerState, _: &mut SessionState, request: &ReadRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("read request {:#?}", request);

        // Read nodes and their attributes
        // produce datavalues in response

        Err(&BAD_SERVICE_UNSUPPORTED)
    }
}
