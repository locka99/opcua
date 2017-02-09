use opcua_core::types::*;
use opcua_core::services::*;

use ::{Server};
use comms::tcp_transport::*;
use services::view::ViewService;

use super::*;

#[test]
fn browse_nodes() {
    let server = Server::new(&ServerConfig::default_anonymous());
    let tcp_session = TcpTransport::new(&server.server_state);

    let view = ViewService::new();
    {
        let mut session_state = tcp_session.session_state.lock().unwrap();
        let mut server_state = tcp_session.server_state.lock().unwrap();

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
        let request = BrowseRequest {
            request_header: request_header,
            view: ViewDescription {
                view_id: NodeId::null(),
                timestamp: DateTime::now(),
                view_version: 0,
            },
            requested_max_references_per_node: 1000,
            nodes_to_browse: Some(vec![
                BrowseDescription {
                    node_id: ObjectId::ObjectsFolder.as_node_id(),
                    browse_direction: BrowseDirection::Forward,
                    reference_type_id: ReferenceTypeId::HasChild.as_node_id(),
                    include_subtypes: true,
                    node_class_mask: 0,
                    result_mask: 0,
                }])
        };

        let result = view.browse(&mut server_state, &mut session_state, &request);
        println!("Result of browse = {:#?}", result);
        assert!(false);
    }
}
