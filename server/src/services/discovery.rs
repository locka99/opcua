use std::result::Result;

use opcua_types::*;

use server::ServerState;
use session::Session;
use services::Service;

pub struct DiscoveryService {}

impl Service for DiscoveryService {}

impl DiscoveryService {
    pub fn new() -> DiscoveryService {
        DiscoveryService {}
    }

    pub fn get_endpoints(&self, server_state: &mut ServerState, _: &mut Session, request: GetEndpointsRequest) -> Result<SupportedMessage, StatusCode> {
        let endpoints = server_state.endpoints(request.profile_uris);
        let response = GetEndpointsResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            endpoints,
        };
        Ok(SupportedMessage::GetEndpointsResponse(response))
    }
}

