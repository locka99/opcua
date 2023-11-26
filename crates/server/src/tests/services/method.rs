use crate::supported_message_as;
use crate::sync::*;
use crate::types::{
    node_ids::{MethodId, ObjectId},
    service_types::{CallMethodRequest, CallMethodResult, CallRequest, CallResponse},
    status_code::StatusCode,
};

use crate::server::services::{
    method::MethodService, monitored_item::MonitoredItemService, subscription::SubscriptionService,
};

use super::*;

fn do_method_service_test<F>(f: F)
where
    F: FnOnce(
        Arc<RwLock<ServerState>>,
        Arc<RwLock<SessionManager>>,
        Arc<RwLock<Session>>,
        Arc<RwLock<AddressSpace>>,
        &MethodService,
    ),
{
    let st = ServiceTest::new();

    let s = MethodService::new();

    let (server_state, session) = st.get_server_state_and_session();
    let address_space = st.address_space.clone();
    let session_manager = st.session_manager.clone();
    f(server_state, session_manager, session, address_space, &s);
}

fn new_call_method_request<S, T>(
    object_id: S,
    method_id: T,
    input_arguments: Option<Vec<Variant>>,
) -> CallMethodRequest
where
    S: Into<NodeId>,
    T: Into<NodeId>,
{
    CallMethodRequest {
        object_id: object_id.into(),
        method_id: method_id.into(),
        input_arguments,
    }
}

fn create_subscription_request() -> CreateSubscriptionRequest {
    CreateSubscriptionRequest {
        request_header: RequestHeader::dummy(),
        requested_publishing_interval: 100f64,
        requested_lifetime_count: 100,
        requested_max_keep_alive_count: 100,
        max_notifications_per_publish: 5,
        publishing_enabled: true,
        priority: 0,
    }
}

fn create_monitored_items_request<T>(
    subscription_id: u32,
    client_handle: u32,
    node_id: T,
) -> CreateMonitoredItemsRequest
where
    T: 'static + Into<NodeId>,
{
    CreateMonitoredItemsRequest {
        request_header: RequestHeader::dummy(),
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
fn call_single(
    s: &MethodService,
    server_state: Arc<RwLock<ServerState>>,
    session_manager: Arc<RwLock<SessionManager>>,
    session: Arc<RwLock<Session>>,
    address_space: Arc<RwLock<AddressSpace>>,
    request: CallMethodRequest,
) -> Result<CallMethodResult, StatusCode> {
    let session_id = {
        let session = trace_read_lock!(session);
        session.session_id().clone()
    };
    let response = s.call(
        server_state,
        &session_id,
        session_manager,
        address_space,
        &CallRequest {
            request_header: RequestHeader::dummy(),
            methods_to_call: Some(vec![request]),
        },
    );
    let response: CallResponse = supported_message_as!(response, CallResponse);
    Ok(response.results.unwrap().remove(0))
}

#[test]
fn call_getmonitoreditems_invalid_object_id() {
    do_method_service_test(|server_state, session_manager, session, address_space, s| {
        // Call without a valid object id
        let request =
            new_call_method_request(NodeId::null(), MethodId::Server_GetMonitoredItems, None);
        let response = call_single(
            s,
            server_state,
            session_manager,
            session,
            address_space,
            request,
        )
        .unwrap();
        assert_eq!(response.status_code, StatusCode::BadNodeIdUnknown);
    });
}

#[test]
fn call_getmonitoreditems_invalid_method_id() {
    do_method_service_test(|server_state, session_manager, session, address_space, s| {
        // Call without a valid method id
        let request = new_call_method_request(ObjectId::Server, NodeId::null(), None);
        let response = call_single(
            s,
            server_state,
            session_manager,
            session,
            address_space,
            request,
        )
        .unwrap();
        assert_eq!(response.status_code, StatusCode::BadMethodInvalid);
    });
}

#[test]
fn call_getmonitoreditems_no_args() {
    do_method_service_test(|server_state, session_manager, session, address_space, s| {
        // Call without args
        let request =
            new_call_method_request(ObjectId::Server, MethodId::Server_GetMonitoredItems, None);
        let response = call_single(
            s,
            server_state,
            session_manager,
            session,
            address_space,
            request,
        )
        .unwrap();
        assert_eq!(response.status_code, StatusCode::BadArgumentsMissing);
    });
}

#[test]
fn call_getmonitoreditems_too_many_args() {
    do_method_service_test(|server_state, session_manager, session, address_space, s| {
        // Call with too many args
        let args: Vec<Variant> = vec![100.into(), 100.into()];
        let request = new_call_method_request(
            ObjectId::Server,
            MethodId::Server_GetMonitoredItems,
            Some(args),
        );
        let response = call_single(
            s,
            server_state,
            session_manager,
            session,
            address_space,
            request,
        )
        .unwrap();
        assert_eq!(response.status_code, StatusCode::BadTooManyArguments);
    });
}

#[test]
fn call_getmonitoreditems_incorrect_args() {
    do_method_service_test(|server_state, session_manager, session, address_space, s| {
        // Call with incorrect arg
        let args: Vec<Variant> = vec![100u8.into()];
        let request = new_call_method_request(
            ObjectId::Server,
            MethodId::Server_GetMonitoredItems,
            Some(args),
        );
        let response = call_single(
            s,
            server_state,
            session_manager,
            session,
            address_space,
            request,
        )
        .unwrap();
        assert_eq!(response.status_code, StatusCode::BadInvalidArgument);
    });
}

#[test]
fn call_getmonitoreditems_invalid_subscription_id() {
    do_method_service_test(|server_state, session_manager, session, address_space, s| {
        // Call with invalid subscription id
        let args: Vec<Variant> = vec![100u32.into()];
        let request = new_call_method_request(
            ObjectId::Server,
            MethodId::Server_GetMonitoredItems,
            Some(args),
        );
        let response = call_single(
            s,
            server_state,
            session_manager,
            session,
            address_space,
            request,
        )
        .unwrap();
        assert_eq!(response.status_code, StatusCode::BadSubscriptionIdInvalid);
    });
}

#[test]
fn call_getmonitoreditems() {
    do_method_service_test(|server_state, session_manager, session, address_space, s| {
        // Call with valid subscription id
        {
            let ss = SubscriptionService::new();
            let mis = MonitoredItemService::new();

            // Create a subscription with some monitored items where client handle is distinct
            let subscription_id = {
                let request = create_subscription_request();
                let response: CreateSubscriptionResponse = supported_message_as!(
                    ss.create_subscription(server_state.clone(), session.clone(), &request),
                    CreateSubscriptionResponse
                );
                response.subscription_id
            };

            // Create a monitored item
            let monitored_item_id = {
                let request = create_monitored_items_request(
                    subscription_id,
                    999,
                    VariableId::Server_ServerStatus_CurrentTime,
                );
                let response: CreateMonitoredItemsResponse = supported_message_as!(
                    mis.create_monitored_items(
                        server_state.clone(),
                        session.clone(),
                        address_space.clone(),
                        &request
                    ),
                    CreateMonitoredItemsResponse
                );
                response.results.unwrap()[0].monitored_item_id
            };

            // Call to get monitored items and verify handles
            let args: Vec<Variant> = vec![subscription_id.into()];
            let request = new_call_method_request(
                ObjectId::Server,
                MethodId::Server_GetMonitoredItems,
                Some(args),
            );
            let response = call_single(
                s,
                server_state.clone(),
                session_manager.clone(),
                session.clone(),
                address_space.clone(),
                request,
            )
            .unwrap();
            assert_eq!(response.status_code, StatusCode::Good);

            // There should be two output args, each a vector of u32
            let mut result = response.output_arguments.unwrap();
            let server_handles = result.remove(0);
            let client_handles = result.remove(0);

            if let Variant::Array(array) = server_handles {
                let mut values = array.values;
                assert_eq!(values.len(), 1);
                assert_eq!(Variant::from(monitored_item_id), values.pop().unwrap());
            } else {
                assert!(false);
            }

            if let Variant::Array(array) = client_handles {
                let mut values = array.values;
                assert_eq!(values.len(), 1);
                assert_eq!(Variant::from(999u32), values.pop().unwrap());
            } else {
                assert!(false);
            }
        }
    });
}

#[test]
fn call_resend_data() {
    do_method_service_test(|server_state, session_manager, session, address_space, s| {
        // Call without a valid object id
        {
            let request =
                new_call_method_request(NodeId::null(), MethodId::Server_ResendData, None);
            let response = call_single(
                s,
                server_state.clone(),
                session_manager.clone(),
                session.clone(),
                address_space.clone(),
                request,
            )
            .unwrap();
            assert_eq!(response.status_code, StatusCode::BadNodeIdUnknown);
        }

        // Call with invalid subscription id
        {
            let args: Vec<Variant> = vec![100u32.into()];
            let request =
                new_call_method_request(ObjectId::Server, MethodId::Server_ResendData, Some(args));
            let response = call_single(
                s,
                server_state.clone(),
                session_manager.clone(),
                session.clone(),
                address_space.clone(),
                request,
            )
            .unwrap();
            assert_eq!(response.status_code, StatusCode::BadSubscriptionIdInvalid);
        }

        // Call with valid subscription id
        {
            let ss = SubscriptionService::new();
            let _mis = MonitoredItemService::new();

            // Create a subscription with some monitored items where client handle is distinct
            let subscription_id = {
                let request = create_subscription_request();
                let response: CreateSubscriptionResponse = supported_message_as!(
                    ss.create_subscription(server_state.clone(), session.clone(), &request),
                    CreateSubscriptionResponse
                );
                response.subscription_id
            };

            // Call to get monitored items and verify handles
            let args: Vec<Variant> = vec![subscription_id.into()];
            let request =
                new_call_method_request(ObjectId::Server, MethodId::Server_ResendData, Some(args));
            let response = call_single(
                s,
                server_state.clone(),
                session_manager.clone(),
                session.clone(),
                address_space.clone(),
                request,
            )
            .unwrap();
            assert_eq!(response.status_code, StatusCode::Good);
        }
    });
}
