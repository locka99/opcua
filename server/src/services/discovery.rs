use std::result::Result;

use opcua_types::*;
use opcua_types::status_code::StatusCode;

use crate::{state::ServerState, services::Service};

/// The discovery service. Allows a server to return the endpoints that it supports.
pub(crate) struct DiscoveryService;

impl Service for DiscoveryService {
    fn name(&self) -> String { String::from("DiscoveryService") }
}

impl DiscoveryService {
    pub fn new() -> DiscoveryService {
        DiscoveryService {}
    }

    pub fn get_endpoints(&self, server_state: &ServerState, request: &GetEndpointsRequest) -> Result<SupportedMessage, StatusCode> {
        // TODO some of the arguments in the request are ignored
        //  endpointUrl - for diagnostics and to determine what urls to return in response
        //  localeIds - list of locales to use for human readable strings (in the endpoint descriptions)
        let endpoints = server_state.endpoints(&request.profile_uris);
        let response = GetEndpointsResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            endpoints,
        };
        Ok(response.into())
    }
}

