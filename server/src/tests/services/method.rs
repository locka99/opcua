use opcua_core;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::{CallRequest, CallResponse, CallMethodRequest, CallMethodResult};
use opcua_types::node_ids::{ObjectId, MethodId};

use super::*;
use services::method::MethodService;

fn new_call_method_request(object_id: NodeId, method_id: NodeId, input_arguments: Option<Vec<Variant>>) -> CallMethodRequest {
    CallMethodRequest {
        object_id,
        method_id,
        input_arguments,
    }
}

/// This is a convenience for tests
fn call_single(s: &MethodService, address_space: &AddressSpace, server_state: &ServerState, session: &Session, request: CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
    let response = s.call(address_space, server_state, session, CallRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        methods_to_call: Some(vec![request]),
    })?;
    let response: CallResponse = supported_message_as!(response, CallResponse);
    Ok(response.results.unwrap().remove(0))
}

// #[test]
fn call_getmonitoreditems() {
    opcua_core::init_logging();

    let st = ServiceTest::new();

    let s = MethodService::new();

    let (server_state, session) = st.get_server_state_and_session();
    let address_space = st.server.address_space.write().unwrap();

    // Call without a valid object id
    {
        let request = new_call_method_request(NodeId::null(), MethodId::Server_GetMonitoredItems.into(), None);
        let response = call_single(&s, &address_space, &server_state, &session, request).unwrap();
        assert_eq!(response.status_code, BadNodeIdUnknown);
    }

    // Call without a valid method id
    {
        let request = new_call_method_request(ObjectId::Server.into(), NodeId::null(), None);
        let response = call_single(&s, &address_space, &server_state, &session, request).unwrap();
        assert_eq!(response.status_code, BadMethodInvalid);
    }

    // Call without args
    {
        let request = new_call_method_request(ObjectId::Server.into(), MethodId::Server_GetMonitoredItems.into(), None);
        let response = call_single(&s, &address_space, &server_state, &session, request).unwrap();
        assert_eq!(response.status_code, BadArgumentsMissing);
    }

    // Call with too many args
    {
        let args: Vec<Variant> = vec![100.into(), 100.into()];
        let request = new_call_method_request(ObjectId::Server.into(), MethodId::Server_GetMonitoredItems.into(), Some(args));
        let response = call_single(&s, &address_space, &server_state, &session, request).unwrap();
        assert_eq!(response.status_code, BadTooManyArguments);
    }

    // Call with incorrect arg
    {
        let args: Vec<Variant> = vec![100u8.into()];
        let request = new_call_method_request(ObjectId::Server.into(), MethodId::Server_GetMonitoredItems.into(), Some(args));
        let response = call_single(&s, &address_space, &server_state, &session, request).unwrap();
        assert_eq!(response.status_code, BadInvalidArgument);
    }

    // Call with invalid subscription id
    {
        let args: Vec<Variant> = vec![100u32.into()];
        let request = new_call_method_request(ObjectId::Server.into(), MethodId::Server_GetMonitoredItems.into(), Some(args));
        let response = call_single(&s, &address_space, &server_state, &session, request).unwrap();
        assert_eq!(response.status_code, BadSubscriptionIdInvalid);
    }

    // Call with valid subscription id
    {
        // Create a subscription with some monitored items where client handle is distinct

        // Call to get monitored items and verify handles
    }
}
