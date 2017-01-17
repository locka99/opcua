use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::services::discovery::*;
use opcua_core::comms::*;

use std::result::Result;

pub struct DiscoveryService {}

impl DiscoveryService {
    pub fn handle_get_endpoints_request(&self, request: &GetEndpointsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("handle_get_endpoints_request");
        let response = GetEndpointsResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
            endpoints: None,
        };
        Ok(SupportedMessage::GetEndpointsResponse(response))
    }
}

