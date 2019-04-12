use opcua_types::{
    status_code::StatusCode,
    service_types::{CallRequest, CallResponse, CallMethodRequest, CallMethodResult},
    node_ids::{ObjectId, MethodId},
};

use super::*;

use crate::services::{
    method::MethodService,
    subscription::SubscriptionService,
    monitored_item::MonitoredItemService,
};

fn do_method_service_test<F>(f: F)
    where F: FnOnce(&mut super::ServerState, &mut Session, &mut AddressSpace, &MethodService)
{
    let st = ServiceTest::new();

    let s = MethodService::new();

    let (mut server_state, mut session) = st.get_server_state_and_session();
    let mut address_space = st.address_space.write().unwrap();

    f(&mut server_state, &mut session, &mut address_space, &s);
}

fn new_call_method_request<S, T>(object_id: S, method_id: T, input_arguments: Option<Vec<Variant>>) -> CallMethodRequest
    where S: Into<NodeId>, T: Into<NodeId> {
    CallMethodRequest {
        object_id: object_id.into(),
        method_id: method_id.into(),
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

fn create_monitored_items_request<T>(subscription_id: u32, client_handle: u32, node_id: T) -> CreateMonitoredItemsRequest where T: 'static + Into<NodeId> {
    CreateMonitoredItemsRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id,
        timestamps_to_return: TimestampsToReturn::Both,
        items_to_create: Some(vec![MonitoredItemCreateRequest {
            item_to_monitor: ReadValueId {
                node_id: node_id.into(),
                attribute_id: AttributeId::Value as u32,
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
fn call_single(s: &MethodService, address_space: &mut AddressSpace, server_state: &ServerState, session: &mut Session, request: CallMethodRequest) -> Result<CallMethodResult, StatusCode> {
    let response = s.call(address_space, server_state, session, &CallRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        methods_to_call: Some(vec![request]),
    })?;
    let response: CallResponse = supported_message_as!(response, CallResponse);
    Ok(response.results.unwrap().remove(0))
}

#[test]
fn call_getmonitoreditems() {
    do_method_service_test(|server_state, session, address_space, s| {
        // Call without a valid object id
        {
            let request = new_call_method_request(NodeId::null(), MethodId::Server_GetMonitoredItems, None);
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::BadNodeIdUnknown);
        }

        // Call without a valid method id
        {
            let request = new_call_method_request(ObjectId::Server, NodeId::null(), None);
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::BadMethodInvalid);
        }

        // Call without args
        {
            let request = new_call_method_request(ObjectId::Server, MethodId::Server_GetMonitoredItems, None);
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::BadArgumentsMissing);
        }

        // Call with too many args
        {
            let args: Vec<Variant> = vec![100.into(), 100.into()];
            let request = new_call_method_request(ObjectId::Server, MethodId::Server_GetMonitoredItems, Some(args));
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::BadTooManyArguments);
        }

        // Call with incorrect arg
        {
            let args: Vec<Variant> = vec![100u8.into()];
            let request = new_call_method_request(ObjectId::Server, MethodId::Server_GetMonitoredItems, Some(args));
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::BadInvalidArgument);
        }

        // Call with invalid subscription id
        {
            let args: Vec<Variant> = vec![100u32.into()];
            let request = new_call_method_request(ObjectId::Server, MethodId::Server_GetMonitoredItems, Some(args));
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::BadSubscriptionIdInvalid);
        }

        // Call with valid subscription id
        {
            let ss = SubscriptionService::new();
            let mis = MonitoredItemService::new();

            // Create a subscription with some monitored items where client handle is distinct
            let subscription_id = {
                let request = create_subscription_request();
                let response: CreateSubscriptionResponse = supported_message_as!(ss.create_subscription(server_state, session, &request).unwrap(), CreateSubscriptionResponse);
                response.subscription_id
            };

            // Create a monitored item
            let monitored_item_id = {
                let request = create_monitored_items_request(subscription_id, 999, VariableId::Server_ServerStatus_CurrentTime);
                let response: CreateMonitoredItemsResponse = supported_message_as!(mis.create_monitored_items(session, &request).unwrap(), CreateMonitoredItemsResponse);
                response.results.unwrap()[0].monitored_item_id
            };

            // Call to get monitored items and verify handles
            let args: Vec<Variant> = vec![subscription_id.into()];
            let request = new_call_method_request(ObjectId::Server, MethodId::Server_GetMonitoredItems, Some(args));
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::Good);

            // There should be two output args, each a vector of u32
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
    });
}


#[test]
fn call_resend_data() {
    do_method_service_test(|server_state, session, address_space, s| {
        // Call without a valid object id
        {
            let request = new_call_method_request(NodeId::null(), MethodId::Server_ResendData, None);
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::BadNodeIdUnknown);
        }


        // Call with invalid subscription id
        {
            let args: Vec<Variant> = vec![100u32.into()];
            let request = new_call_method_request(ObjectId::Server, MethodId::Server_ResendData, Some(args));
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::BadSubscriptionIdInvalid);
        }

        // Call with valid subscription id
        {
            let ss = SubscriptionService::new();
            let _mis = MonitoredItemService::new();

            // Create a subscription with some monitored items where client handle is distinct
            let subscription_id = {
                let request = create_subscription_request();
                let response: CreateSubscriptionResponse = supported_message_as!(ss.create_subscription(server_state, session, &request).unwrap(), CreateSubscriptionResponse);
                response.subscription_id
            };

            // Call to get monitored items and verify handles
            let args: Vec<Variant> = vec![subscription_id.into()];
            let request = new_call_method_request(ObjectId::Server, MethodId::Server_ResendData, Some(args));
            let response = call_single(s, address_space, &server_state, session, request).unwrap();
            assert_eq!(response.status_code, StatusCode::Good);
        }
    });
}
