use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use types::*;
use server::ServerState;

pub struct DiscoveryService {}

impl DiscoveryService {
    pub fn new() -> DiscoveryService {
        DiscoveryService {}
    }

    pub fn get_endpoints(&self, server_state: &mut ServerState, _: &mut SessionState, request: &GetEndpointsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("get_endpoints");
        let response = GetEndpointsResponse {
            response_header: ResponseHeader::new(&DateTime::now(), &request.request_header),
            endpoints: Some(server_state.endpoints()),
        };
        Ok(SupportedMessage::GetEndpointsResponse(response))
    }
}

