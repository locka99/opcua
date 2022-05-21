use crate::server::services::discovery::DiscoveryService;
use crate::supported_message_as;
use crate::sync::*;
use crate::types::UAString;

use super::*;

fn do_discovery_service_test<F>(f: F)
where
    F: FnOnce(Arc<RwLock<ServerState>>, Arc<RwLock<Session>>, &DiscoveryService),
{
    let st = ServiceTest::new();
    let (server_state, session) = st.get_server_state_and_session();

    let ds = DiscoveryService::new();

    f(server_state, session, &ds);
}

#[test]
fn get_endpoints() {
    do_discovery_service_test(|server_state, _session, ds| {
        let request = GetEndpointsRequest {
            request_header: make_request_header(),
            endpoint_url: UAString::from("opc.tcp://localhost:4855/"),
            locale_ids: None,
            profile_uris: None,
        };

        let result = ds.get_endpoints(server_state, &request);
        let result = supported_message_as!(result, GetEndpointsResponse);

        // Verify endpoints
        let endpoints = result.endpoints.unwrap();
        assert!(!endpoints.is_empty());

        debug!("Endpoints = {:#?}", endpoints);
    });
}

#[test]
fn find_servers() {
    do_discovery_service_test(|server_state, _session, ds| {
        // This is a very basic test
        let request = FindServersRequest {
            request_header: make_request_header(),
            endpoint_url: Default::default(),
            locale_ids: None,
            server_uris: None,
        };
        let result = ds.find_servers(server_state, &request);

        let response = supported_message_as!(result, FindServersResponse);
        let servers = response.servers.unwrap();
        assert_eq!(servers.len(), 1);

        // Verify application servers have the fields we expect
        servers.iter().for_each(|s| {
            let discovery_urls = s.discovery_urls.as_ref().unwrap();
            assert!(!discovery_urls.is_empty());
            assert_eq!(s.application_type, ApplicationType::Server);
            assert_eq!(s.application_name.text.as_ref(), "OPC UA Sample Server");
            assert_eq!(s.application_uri.as_ref(), "urn:OPC UA Sample Server");
            assert_eq!(s.product_uri.as_ref(), "urn:OPC UA Sample Server Testkit");
        });

        // TODO other requests should exercise those filters
    });
}

#[test]
fn discovery_test() {
    do_discovery_service_test(|server_state, _session, ds| {
        let endpoint_url = UAString::from("opc.tcp://localhost:4855/");
        {
            let request = GetEndpointsRequest {
                request_header: make_request_header(),
                endpoint_url: endpoint_url.clone(),
                locale_ids: None,
                profile_uris: None,
            };

            let result = ds.get_endpoints(server_state.clone(), &request);
            let result = supported_message_as!(result, GetEndpointsResponse);

            // Verify endpoints
            let endpoints = result.endpoints.unwrap();
            assert!(!endpoints.is_empty());
            assert_eq!(endpoints.len(), 12);
        }

        // specify profile ids in request
        {
            // Enter some nonsensical profile uris and expect nothing back
            let profile_uris = vec![UAString::from("xxxxxx")];
            let request = GetEndpointsRequest {
                request_header: make_request_header(),
                endpoint_url: endpoint_url.clone(),
                locale_ids: None,
                profile_uris: Some(profile_uris),
            };
            let result = ds.get_endpoints(server_state.clone(), &request);
            let result = supported_message_as!(result, GetEndpointsResponse);
            assert!(result.endpoints.is_none());

            // Enter the binary transport profile and expect the endpoints
            let profile_uris = vec![UAString::from(
                "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
            )];
            let request = GetEndpointsRequest {
                request_header: make_request_header(),
                endpoint_url: endpoint_url.clone(),
                locale_ids: None,
                profile_uris: Some(profile_uris),
            };
            let result = ds.get_endpoints(server_state.clone(), &request);
            let result = supported_message_as!(result, GetEndpointsResponse);
            let endpoints = result.endpoints.unwrap();
            assert!(!endpoints.is_empty())
        }
    });
}
