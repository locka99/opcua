use opcua_core::types::*;
use opcua_core::services::discovery::*;
use opcua_core::comms::*;

use std::result::Result;

pub struct DiscoveryService {

}

impl DiscoveryService {
    pub fn handle_get_endpoints_request(&self, get_endpoints_request: &GetEndpointsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        Err(&BAD_SERVICE_UNSUPPORTED)
    }
}

