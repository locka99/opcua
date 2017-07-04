use std::result::Result;

use opcua_types::*;
use opcua_core::comms::*;

use server::ServerState;
use session::Session;

pub struct DiscoveryService {}

impl DiscoveryService {
    pub fn new() -> DiscoveryService {
        DiscoveryService {}
    }

    pub fn get_endpoints(&self, server_state: &mut ServerState, _: &mut Session, request: GetEndpointsRequest) -> Result<SupportedMessage, StatusCode> {
        let service_status = GOOD;
        let response = GetEndpointsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            endpoints: Some(server_state.endpoints()),
        };
        Ok(SupportedMessage::GetEndpointsResponse(response))
    }
}

