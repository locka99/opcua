use opcua_core::comms::*;
use opcua_core::types::*;
use opcua_core::services::*;

use server::*;
use comms::tcp_transport::*;
use services::view::ViewService;

use super::*;

fn make_browse_request(nodes: Vec<NodeId>, browse_direction: BrowseDirection, reference_type: ReferenceTypeId) -> BrowseRequest {
    let request_header = RequestHeader {
        authentication_token: SessionAuthenticationToken {
            token: NodeId::new_numeric(0, 99),
        },
        timestamp: DateTime::now(),
        request_handle: 1,
        return_diagnostics: 0,
        audit_entry_id: UAString::null(),
        timeout_hint: 123456,
        additional_header: ExtensionObject::null(),
    };
    let mut nodes_to_browse = Vec::with_capacity(nodes.len());
    for n in nodes {
        nodes_to_browse.push(BrowseDescription {
            node_id: n.clone(),
            browse_direction: browse_direction,
            reference_type_id: reference_type.as_node_id(),
            include_subtypes: true,
            node_class_mask: 0xff,
            result_mask: 0xff,
        });
    }
    BrowseRequest {
        request_header: request_header,
        view: ViewDescription {
            view_id: NodeId::null(),
            timestamp: DateTime::now(),
            view_version: 0,
        },
        requested_max_references_per_node: 1000,
        nodes_to_browse: Some(nodes_to_browse)
    }
}

#[test]
fn browse_nodes() {
    let server = Server::new(&ServerConfig::default_anonymous());
    let tcp_session = TcpTransport::new(&server.server_state);

    let view = ViewService::new();
    {
        let mut session_state = tcp_session.session_state.lock().unwrap();
        let mut server_state = tcp_session.server_state.lock().unwrap();

        {
            let mut address_space = server_state.address_space.lock().unwrap();
            add_sample_vars_to_address_space(&mut address_space);
        }

        let request = make_browse_request(vec![ObjectId::RootFolder.as_node_id()], BrowseDirection::Forward, ReferenceTypeId::Organizes);
        println!("Browse Request = {:#?}", request);
        let result = view.browse(&mut server_state, &mut session_state, &request);
        assert!(result.is_ok());

        let result = result.unwrap();
        println!("Browse Response = {:#?}", result);

        let result = match result {
            SupportedMessage::BrowseResponse(result) => result,
            _ => {
                panic!("Wrong response")
            }
        };

        assert!(result.results.is_some());

        let results = result.results.unwrap();
        assert_eq!(results.len(), 1);

        assert!(results[0].references.is_some());
        let references = results[0].references.as_ref().unwrap();
        assert_eq!(references.len(), 3);

        // Expect to see refs to
        // Objects/
        // Types/
        // Views/

        let r1 = &references[0];
        assert_eq!(r1.browse_name, QualifiedName::new(0, "Objects"));
        let r2 = &references[1];
        assert_eq!(r2.browse_name, QualifiedName::new(0, "Types"));
        let r3 = &references[2];
        assert_eq!(r3.browse_name, QualifiedName::new(0, "Views"));
    }
}
