use opcua_types::UAString;

use super::*;
use services::discovery::DiscoveryService;

#[test]
fn discovery_test() {
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();

    let ds = DiscoveryService::new();

    {
        let request = GetEndpointsRequest {
            request_header: make_request_header(),
            endpoint_url: UAString::from_str(""),
            locale_ids: None,
            profile_uris: None,
        };

        let result = ds.get_endpoints(&mut server_state, &mut session, request);
        assert!(result.is_ok());
        let result = supported_message_as!(result.unwrap(), GetEndpointsResponse);

        // Verify endpoints
        let endpoints = result.endpoints.unwrap();
        assert!(!endpoints.is_empty())
    }

    // TODO specify localeids
    {
        let locale_ids = vec![];
        let request = GetEndpointsRequest {
            request_header: make_request_header(),
            endpoint_url: UAString::from_str(""),
            locale_ids: Some(locale_ids),
            profile_uris: None,
        };

        let result = ds.get_endpoints(&mut server_state, &mut session, request);
        assert!(result.is_ok());
        let result = supported_message_as!(result.unwrap(), GetEndpointsResponse);
    }

    // TODO specify profile ids
    {
        // Enter some nonsensical profile uris and expect nothing back
        let profile_uris = vec![];
        let request = GetEndpointsRequest {
            request_header: make_request_header(),
            endpoint_url: UAString::from_str(""),
            locale_ids: None,
            profile_uris: Some(profile_uris),
        };
        let result = ds.get_endpoints(&mut server_state, &mut session, request);
        assert!(result.is_ok());
        let result = supported_message_as!(result.unwrap(), GetEndpointsResponse);
        // TODO
        //let endpoints = result.endpoints.unwrap();
        //assert!(endpoints.is_empty())
    }
}