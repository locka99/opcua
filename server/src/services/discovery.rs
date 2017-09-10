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

        // Filter endpoints based on profile_uris
        let endpoints = if let Some(profile_uris) = request.profile_uris {
            // As we only support binary transport, the result is None if the supplied profile_uris does not contain that profile
            let found_binary_transport = profile_uris.iter().find(|profile_uri| {
                profile_uri.as_ref() == profiles::TRANSPORT_PROFILE_URI_BINARY
            });
            if found_binary_transport.is_some() {
                Some(server_state.endpoints())
            }
            else {
                None
            }
        }
        else {
            Some(server_state.endpoints())
        };

        let response = GetEndpointsResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            endpoints,
        };
        Ok(SupportedMessage::GetEndpointsResponse(response))
    }
}

