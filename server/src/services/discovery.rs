use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::services::discovery::*;
use opcua_core::comms::*;

use std::result::Result;

pub struct DiscoveryService {}

impl DiscoveryService {
    pub fn handle_get_endpoints_request(&self, request: &GetEndpointsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("handle_get_endpoints_request");

        // TODO get from session
        let endpoint = EndpointDescription {
            endpoint_url: UAString::from_str("opc.tcp://127.0.0.1:1234"),
            server: ApplicationDescription {
                application_uri: UAString::from_str("opc.tcp://127.0.0.1:1234"),
                product_uri: UAString::null(),
                application_name: LocalizedText {
                    locale: UAString::from_str("en-US"),
                    text: UAString::from_str("FIXME"),
                },
                application_type: ApplicationType::SERVER,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
            },
            server_certificate: ApplicationInstanceCertificate {
                certificate: UAString::null(),
            },
            security_mode: MessageSecurityMode::None,
            security_policy_uri: UAString::null(),
            user_identity_tokens: None,
            transport_profile_uri: UAString::from_str("opc.tcp"),
            security_level: 0,
        };
        let endpoints = vec![endpoint];

        let response = GetEndpointsResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
            endpoints: Some(endpoints),
        };
        Ok(SupportedMessage::GetEndpointsResponse(response))
    }
}

