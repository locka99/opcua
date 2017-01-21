use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use server::ServerState;
use tcp_session::SessionState;

pub struct DiscoveryService {}

impl DiscoveryService {
    pub fn new() -> DiscoveryService {
        DiscoveryService {}
    }

    pub fn handle_get_endpoints_request(&self, server_state: &mut ServerState, session_state: &mut SessionState, request: &GetEndpointsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("handle_get_endpoints_request");

        // server_state.get_endpoints().clone()
        // TODO get from server state

        let server_certificate = server_state.server_certificate.clone();


        let endpoint = EndpointDescription {
            endpoint_url: UAString::from_str("opc.tcp://127.0.0.1:1234/xxx"),
            server: ApplicationDescription {
                application_uri: UAString::from_str("http://localhost/"),
                product_uri: UAString::null(),
                application_name: LocalizedText {
                    locale: UAString::null(),
                    text: UAString::from_str("Rust OPC UA"),
                },
                application_type: ApplicationType::SERVER,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
            },
            server_certificate: server_certificate,
            security_mode: MessageSecurityMode::None,
            security_policy_uri: SecurityPolicy::None.to_string(),
            user_identity_tokens: None,
            transport_profile_uri: UAString::from_str("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"),
            security_level: 1,
        };
        let endpoints = vec![endpoint];

        let response = GetEndpointsResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
            endpoints: Some(endpoints),
        };
        Ok(SupportedMessage::GetEndpointsResponse(response))
    }
}

