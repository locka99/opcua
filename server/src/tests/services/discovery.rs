use opcua_types::UAString;

use super::*;
use crate::services::discovery::DiscoveryService;

#[test]
fn get_endpoints() {
    let st = ServiceTest::new();
    let (mut server_state, _) = st.get_server_state_and_session();

    let ds = DiscoveryService::new();

    {
        let request = GetEndpointsRequest {
            request_header: make_request_header(),
            endpoint_url: UAString::from("opc.tcp://localhost:4855/"),
            locale_ids: None,
            profile_uris: None,
        };

        let result = ds.get_endpoints(&mut server_state, &request);
        assert!(result.is_ok());
        let result = supported_message_as!(result.unwrap(), GetEndpointsResponse);

        // Verify endpoints
        let endpoints = result.endpoints.unwrap();
        assert!(!endpoints.is_empty());

        debug!("Endpoints = {:#?}", endpoints);
    }
}

#[test]
fn discovery_test() {
    let st = ServiceTest::new();
    let (mut server_state, _) = st.get_server_state_and_session();

    let ds = DiscoveryService::new();

    {
        let request = GetEndpointsRequest {
            request_header: make_request_header(),
            endpoint_url: UAString::from(""),
            locale_ids: None,
            profile_uris: None,
        };

        let result = ds.get_endpoints(&mut server_state, &request);
        assert!(result.is_ok());
        let result = supported_message_as!(result.unwrap(), GetEndpointsResponse);

        // Verify endpoints
        let endpoints = result.endpoints.unwrap();
        assert!(!endpoints.is_empty());
    }

    // specify profile ids in request
    {
        // Enter some nonsensical profile uris and expect nothing back
        let profile_uris = vec![UAString::from("xxxxxx")];
        let request = GetEndpointsRequest {
            request_header: make_request_header(),
            endpoint_url: UAString::from(""),
            locale_ids: None,
            profile_uris: Some(profile_uris),
        };
        let result = ds.get_endpoints(&mut server_state, &request);
        assert!(result.is_ok());
        let result = supported_message_as!(result.unwrap(), GetEndpointsResponse);
        assert!(result.endpoints.is_none());

        // Enter the binary transport profile and expect the endpoints
        let profile_uris = vec![UAString::from("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")];
        let request = GetEndpointsRequest {
            request_header: make_request_header(),
            endpoint_url: UAString::from(""),
            locale_ids: None,
            profile_uris: Some(profile_uris),
        };
        let result = ds.get_endpoints(&mut server_state, &request);
        assert!(result.is_ok());
        let result = supported_message_as!(result.unwrap(), GetEndpointsResponse);
        let endpoints = result.endpoints.unwrap();
        assert!(!endpoints.is_empty())
    }
}