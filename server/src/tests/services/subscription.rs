use std::ops::Add;
use std::sync::{Arc, RwLock};
use prelude::*;

use chrono::Utc;

use state::ServerState;
use address_space::AddressSpace;
use services::subscription::SubscriptionService;
use services::monitored_item::MonitoredItemService;

use super::*;

/// A helper that sets up a subscription service test
fn subscription_service() -> (Arc<RwLock<ServerState>>, Arc<RwLock<Session>>, Arc<RwLock<AddressSpace>>, SubscriptionService) {
    let st = ServiceTest::new();
    (st.server_state, st.session, st.address_space, SubscriptionService::new())
}

/// A helper that sets up a subscription and monitored item service test
fn subscription_monitored_item_service() -> (Arc<RwLock<ServerState>>, Arc<RwLock<Session>>, Arc<RwLock<AddressSpace>>, SubscriptionService, MonitoredItemService) {
    let (st, s, ads, ss) = subscription_service();
    (st, s, ads, ss, MonitoredItemService::new())
}

fn create_subscription_request(max_keep_alive_count: UInt32, lifetime_count: UInt32) -> CreateSubscriptionRequest {
    CreateSubscriptionRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        requested_publishing_interval: 100f64,
        requested_lifetime_count: lifetime_count,
        requested_max_keep_alive_count: max_keep_alive_count,
        max_notifications_per_publish: 5,
        publishing_enabled: true,
        priority: 0,
    }
}

fn create_monitored_items_request<T>(subscription_id: UInt32, node_id: T) -> CreateMonitoredItemsRequest where T: 'static + Into<NodeId> {
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
                client_handle: 1,
                sampling_interval: 0.1,
                filter: ExtensionObject::null(),
                queue_size: 1,
                discard_oldest: true,
            },
        }]),
    }
}

#[test]
fn create_modify_destroy_subscription() {
    // TODO Create a subscription, modify it, destroy it
}

/// Creates a subscription with the specified keep alive and lifetime values and compares
/// the revised values to the expected values.
fn keepalive_test(keep_alive: UInt32, lifetime: UInt32, expected_keep_alive: UInt32, expected_lifetime: UInt32) {
    // Create a subscription with a monitored item
    let (server_state, session, _, ss) = subscription_service();
    let mut server_state = trace_write_lock_unwrap!(server_state);
    let mut session = trace_write_lock_unwrap!(session);
    // Create subscription
    let request = create_subscription_request(keep_alive, lifetime);
    let response: CreateSubscriptionResponse = supported_message_as!(ss.create_subscription(&mut server_state, &mut session, request).unwrap(), CreateSubscriptionResponse);
    debug!("{:#?}", response);
    assert_eq!(response.revised_lifetime_count, expected_lifetime);
    assert_eq!(response.revised_max_keep_alive_count, expected_keep_alive);
    assert!(response.revised_lifetime_count >= 3 * response.revised_max_keep_alive_count);
}

#[test]
fn test_revised_keep_alive_lifetime_counts() {
    // Test that the keep alive and lifetime counts are correctly revised from their inputs
    use ::constants::{DEFAULT_KEEP_ALIVE_COUNT, MAX_KEEP_ALIVE_COUNT};
    const MAX_LIFETIME_COUNT: UInt32 = 3 * MAX_KEEP_ALIVE_COUNT;
    const DEFAULT_LIFETIME_COUNT: UInt32 = 3 * DEFAULT_KEEP_ALIVE_COUNT;

    // Expect defaults to hold true
    keepalive_test(0, 0, DEFAULT_KEEP_ALIVE_COUNT, DEFAULT_LIFETIME_COUNT);
    keepalive_test(0, (DEFAULT_KEEP_ALIVE_COUNT * 3) - 1, DEFAULT_KEEP_ALIVE_COUNT, DEFAULT_LIFETIME_COUNT);

    // Expect lifetime to be 3 * keep alive
    keepalive_test(1, 3, 1, 3);
    keepalive_test(1, 4, 1, 4);
    keepalive_test(1, 2, 1, 3);
    keepalive_test(DEFAULT_KEEP_ALIVE_COUNT, 2, DEFAULT_KEEP_ALIVE_COUNT, DEFAULT_LIFETIME_COUNT);

    // Expect max values to be honoured
    keepalive_test(MAX_KEEP_ALIVE_COUNT, 0, MAX_KEEP_ALIVE_COUNT, MAX_LIFETIME_COUNT);
    keepalive_test(MAX_KEEP_ALIVE_COUNT + 1, 0, MAX_KEEP_ALIVE_COUNT, MAX_LIFETIME_COUNT);
}

#[test]
fn publish_with_no_subscriptions() {
    // Create a session
    let (_, session, address_space, ss) = subscription_service();
    let mut session = trace_write_lock_unwrap!(session);
    let address_space = trace_read_lock_unwrap!(address_space);

    let request = PublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_acknowledgements: None, // Option<Vec<SubscriptionAcknowledgement>>,
    };

    // Publish and expect a service fault BadNoSubscription
    let request_id = 1001;
    let response = ss.async_publish(&mut session, request_id, &address_space, request).unwrap().unwrap();
    let response: ServiceFault = supported_message_as!(response, ServiceFault);
    assert_eq!(response.response_header.service_result, StatusCode::BadNoSubscription);
}

#[test]
fn publish_response_subscription() {
    // Create a session
    let (server_state, session, address_space, ss, mis) = subscription_monitored_item_service();
    let mut server_state = trace_write_lock_unwrap!(server_state);
    let mut session = trace_write_lock_unwrap!(session);
    let address_space = trace_read_lock_unwrap!(address_space);

    // Create subscription
    let subscription_id = {
        let request = create_subscription_request(0, 0);
        debug!("{:#?}", request);
        let response: CreateSubscriptionResponse = supported_message_as!(ss.create_subscription(&mut server_state, &mut session, request).unwrap(), CreateSubscriptionResponse);
        debug!("{:#?}", response);
        response.subscription_id
    };

    // Create a monitored item
    {
        let request = create_monitored_items_request(subscription_id, VariableId::Server_ServerStatus_CurrentTime);
        debug!("CreateMonitoredItemsRequest {:#?}", request);
        let response: CreateMonitoredItemsResponse = supported_message_as!(mis.create_monitored_items(&mut session, request).unwrap(), CreateMonitoredItemsResponse);
        debug!("CreateMonitoredItemsResponse {:#?}", response);
        // let result = response.results.unwrap()[0].monitored_item_id;
    }

    // Put the subscription into normal state
    session.subscriptions.get_mut(subscription_id).unwrap().state = SubscriptionState::Normal;

    // Send a publish and expect a publish response containing the subscription
    let notification_message = {
        let request_id = 1001;
        let request = PublishRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            subscription_acknowledgements: None, // Option<Vec<SubscriptionAcknowledgement>>,
        };
        debug!("PublishRequest {:#?}", request);

        // Don't expect a response right away
        let response = ss.async_publish(&mut session, request_id, &address_space, request).unwrap();
        assert!(response.is_none());

        assert!(!session.subscriptions.publish_request_queue.is_empty());

        // Tick subscriptions to trigger a change
        let now = Utc::now().add(chrono::Duration::seconds(2));
        let _ = session.tick_subscriptions(&now, &address_space, TickReason::TickTimerFired);

        // Ensure publish request was processed into a publish response
        assert_eq!(session.subscriptions.publish_request_queue.len(), 0);
        assert_eq!(session.subscriptions.publish_response_queue.len(), 1);

        // Get the response from the queue
        let response = session.subscriptions.publish_response_queue.pop_back().unwrap().response;
        let response: PublishResponse = supported_message_as!(response, PublishResponse);
        debug!("PublishResponse {:#?}", response);

        // We expect the response to contain a non-empty notification
        assert_eq!(response.more_notifications, false);
        assert_eq!(response.subscription_id, subscription_id);
        assert!(response.available_sequence_numbers.is_none());

        response.notification_message
    };
    assert_eq!(notification_message.sequence_number, 1);
    assert!(notification_message.notification_data.is_some());

    // We expect to have one notification
    let notification_data = notification_message.notification_data.as_ref().unwrap();
    assert_eq!(notification_data.len(), 1);

    // We expect the notification to contain one data change notification referring to
    // the monitored item.

    let data_change = notification_data[0].decode_inner::<DataChangeNotification>().unwrap();
    assert!(data_change.monitored_items.is_some());
    let monitored_items = data_change.monitored_items.unwrap();
    assert_eq!(monitored_items.len(), 1);

    // We expect the notification to be about handle 1

    let monitored_item_notification = &monitored_items[0];
    assert_eq!(monitored_item_notification.client_handle, 1);

    // We expect the queue to be empty, because we got an immediate response
    assert!(session.subscriptions.publish_response_queue.is_empty());
}

#[test]
fn publish_keep_alive() {
    // TODO we want to create a subscription with a known keep alive value and ensure
    // that after consecutive empty ticks we get back a keep alive
}

#[test]
fn multiple_publish_response_subscription() {
    // Create a session
//    let (server_state, session, address_space, ss, mis) = subscription_monitored_item_service();
//    let server_state = trace_write_lock_unwrap!(server_state);
//    let session = trace_write_lock_unwrap!(session);
//    let address_space = trace_read_lock_unwrap!(address_space);

    // Send a publish and expect nothing
    // Tick a change
    // Expect a publish response containing the subscription to be pushed
}

// TODO acknowledge an unknown seqid

#[test]
fn republish() {
    // Create a session
    let (server_state, session, _, ss) = subscription_service();
    let mut server_state = trace_write_lock_unwrap!(server_state);
    let mut session = trace_write_lock_unwrap!(session);

    // Create subscription
    let subscription_id = {
        let request = create_subscription_request(0, 0);
        debug!("{:#?}", request);
        let response: CreateSubscriptionResponse = supported_message_as!(ss.create_subscription(&mut server_state, &mut session, request).unwrap(), CreateSubscriptionResponse);
        debug!("{:#?}", response);
        response.subscription_id
    };

    // Add a notification to the subscriptions retransmission queue
    let sequence_number = {
        let monitored_item_notifications = vec![];
        let notification = NotificationMessage::data_change(1, DateTime::now(), monitored_item_notifications);
        let sequence_number = notification.sequence_number;
        session.subscriptions.retransmission_queue().insert(notification.sequence_number, (subscription_id, notification));
        sequence_number
    };

    // try for a notification message known to exist
    let request = RepublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id,
        retransmit_sequence_number: sequence_number,
    };
    let response = ss.republish(&mut session, request).unwrap();
    trace!("republish response {:#?}", response);
    let response: RepublishResponse = supported_message_as!(response, RepublishResponse);
    assert!(response.notification_message.sequence_number != 0);

    // try for a subscription id that does not exist, expect service fault
    let request = RepublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id: subscription_id + 1,
        retransmit_sequence_number: sequence_number,
    };
    let response: ServiceFault = supported_message_as!(ss.republish(&mut session, request).unwrap(), ServiceFault);
    assert_eq!(response.response_header.service_result, StatusCode::BadNoSubscription);

    // try for a sequence nr that does not exist
    let request = RepublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id,
        retransmit_sequence_number: sequence_number + 1,
    };
    let response: ServiceFault = supported_message_as!(ss.republish(&mut session, request).unwrap(), ServiceFault);
    assert_eq!(response.response_header.service_result, StatusCode::BadMessageNotAvailable);
}