use opcua_core;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::{CallRequest, CallResponse, CallMethodRequest, CallMethodResult};
use opcua_types::node_ids::{ObjectId, MethodId};

use super::*;

use services::method::MethodService;
use services::subscription::SubscriptionService;
use services::monitored_item::MonitoredItemService;

fn new_call_method_request(object_id: NodeId, method_id: NodeId, input_arguments: Option<Vec<Variant>>) -> CallMethodRequest {
    CallMethodRequest {
        object_id,
        method_id,
        input_arguments,
    }
}

fn create_subscription_request() -> CreateSubscriptionRequest {
    CreateSubscriptionRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        requested_publishing_interval: 100f64,
        requested_lifetime_count: 100,
        requested_max_keep_alive_count: 100,
        max_notifications_per_publish: 5,
        publishing_enabled: true,
        priority: 0,
    }
}

fn create_monitored_items_request<T>(subscription_id: UInt32, client_handle: UInt32, node_id: T) -> CreateMonitoredItemsRequest where T: 'static + Into<NodeId> {
    CreateMonitoredItemsRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id,
        timestamps_to_return: TimestampsToReturn::Both,
        items_to_create: Some(vec![MonitoredItemCreateRequest {
            item_to_monitor: ReadValueId {
                node_id: node_id.into(),
                attribute_id: AttributeId::Value as UInt32,
                index_range: UAString::null(),
                data_encoding: QualifiedName::null(),
            },
            monitoring_mode: MonitoringMode::Reporting,
            requested_parameters: MonitoringParameters {
                client_handle,
                sampling_interval: 0.1,
                filter: ExtensionObject::null(),
                queue_size: 1,
                discard_oldest: true,
            },
        }]),
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

    let (mut server_state, mut session) = st.get_server_state_and_session();
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
        let ss = SubscriptionService::new();
        let mis = MonitoredItemService::new();

        // Create a subscription with some monitored items where client handle is distinct
        let subscription_id = {
            let request = create_subscription_request();
            let response: CreateSubscriptionResponse = supported_message_as!(ss.create_subscription(&mut server_state, &mut session, request).unwrap(), CreateSubscriptionResponse);
            response.subscription_id
        };

        // Create a monitored item
        let monitored_item_id = {
            let request = create_monitored_items_request(subscription_id, 999, VariableId::Server_ServerStatus_CurrentTime);
            let response: CreateMonitoredItemsResponse = supported_message_as!(mis.create_monitored_items(&mut session, request).unwrap(), CreateMonitoredItemsResponse);
            response.results.unwrap()[0].monitored_item_id
        };

        // Call to get monitored items and verify handles
        let args: Vec<Variant> = vec![subscription_id.into()];
        let request = new_call_method_request(ObjectId::Server.into(), MethodId::Server_GetMonitoredItems.into(), Some(args));
        let response = call_single(&s, &address_space, &server_state, &session, request).unwrap();
        assert_eq!(response.status_code, Good);

        let mut result = response.output_arguments.unwrap();
        let server_handles = result.remove(0);
        let client_handles = result.remove(0);

        if let Variant::Array(mut v) = server_handles {
            assert_eq!(v.len(), 1);
            assert_eq!(Variant::from(monitored_item_id), v.pop().unwrap());
        } else {
            assert!(false);
        }

        if let Variant::Array(mut v) = client_handles {
            assert_eq!(v.len(), 1);
            assert_eq!(Variant::from(999u32), v.pop().unwrap());
        } else {
            assert!(false);
        }
    }
}
