use opcua_core::types::*;
use opcua_core::services::discovery::*;

use std::result::Result;

pub struct DiscoveryService {}

impl DiscoveryService {
    pub fn handle_get_endpoints_request(get_endpoints_request: &GetEndPointsRequest) -> Result<GetEndPointsResponse, &'static StatusCode> {
        Err(&BAD_SERVICE_UNSUPPORTED)
    }
}

