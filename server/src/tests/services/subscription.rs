use prelude::*;

use opcua_core;

use services::subscription::SubscriptionService;
use services::monitored_item::MonitoredItemService;

use super::*;

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

fn create_monitored_items_request<T>(subscription_id: UInt32, node_id: T) -> CreateMonitoredItemsRequest where T: 'static + Into<NodeId> {
    CreateMonitoredItemsRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id: subscription_id,
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

#[test]
fn publish_with_no_subscriptions() {
    opcua_core::init_logging();

    // Create a session
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();
    let address_space = st.get_address_space();

    let request = PublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_acknowledgements: None, // Option<Vec<SubscriptionAcknowledgement>>,
    };

    // Publish and expect a service fault BadNoSubscription
    let request_id = 1001;
    let ss = SubscriptionService::new();
    let response = ss.publish(&mut session, request_id, &address_space, request).unwrap().unwrap();
    let response: ServiceFault = supported_message_as!(response, ServiceFault);
    assert_eq!(response.response_header.service_result, StatusCode::BadNoSubscription);
}

#[test]
fn publish_response_subscription() {
    opcua_core::init_logging();

    // Create a session
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();
    let address_space = st.get_address_space();

    // Create a subscription with a monitored item
    let ss = SubscriptionService::new();
    let mis = MonitoredItemService::new();

    // Create subscription
    let subscription_id = {
        let request = create_subscription_request();
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

    // Send a publish and expect a publish response containing the subscription
    let notification_message = {
        let request_id = 1001;
        let request = PublishRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            subscription_acknowledgements: None, // Option<Vec<SubscriptionAcknowledgement>>,
        };
        debug!("PublishRequest {:#?}", request);

        // Don't expect a response right away
        let response = ss.publish(&mut session, request_id, &address_space, request).unwrap();
        assert!(response.is_none());

        assert!(!session.subscriptions.publish_request_queue.is_empty());

        // Tick subscriptions to trigger a change
        let _ = session.tick_subscriptions(&address_space, TickReason::TickTimerFired);

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

        // We expect the notification to have a sequence number of 1
        response.notification_message
    };
    assert_eq!(notification_message.sequence_number, 1);
    assert!(notification_message.notification_data.is_some());

    // We expect to have one notification
    let notification_data = notification_message.notification_data.as_ref().unwrap();
    assert_eq!(notification_data.len(), 1);

    // We expect the notification to contain one data change notification referring to
    // the monitored item.

    let data_change = notification_data[1].decode_inner::<DataChangeNotification>().unwrap();
    assert!(data_change.monitored_items.is_some());
    let monitored_items = data_change.monitored_items.unwrap();
    assert_eq!(monitored_items.len(), 1);

    // We expect the notification to be about handle 1

    let monitored_item_notification = &monitored_items[0];
    assert_eq!(monitored_item_notification.client_handle, 1);

    // We expect the queue to be empty, because we got an immediate response
    assert!(!session.subscriptions.publish_response_queue.is_empty());
}

#[test]
fn multiple_publish_response_subscription() {
    // Create a session
    let st = ServiceTest::new();
    let (server_state, _) = st.get_server_state_and_session();

    // Create a subscription with a monitored item
    let _ss = SubscriptionService::new();
    let _mis = MonitoredItemService::new();

    // Send a publish and expect nothing
    // Tick a change
    // Expect a publish response containing the subscription to be pushed
}

// TODO acknowledge an unknown seqid

#[test]
fn republish() {
    opcua_core::init_logging();

    // Create a session
    let st = ServiceTest::new();
    let (mut server_state, mut session) = st.get_server_state_and_session();

    // Create a subscription with a monitored item
    let ss = SubscriptionService::new();

    // Create subscription
    let subscription_id = {
        let request = create_subscription_request();
        debug!("{:#?}", request);
        let response: CreateSubscriptionResponse = supported_message_as!(ss.create_subscription(&mut server_state, &mut session, request).unwrap(), CreateSubscriptionResponse);
        debug!("{:#?}", response);
        response.subscription_id
    };

    let sequence_number = 222;

    // Add a notification to the subscriptions retransmission queue
    {
        let monitored_item_notifications = vec![];
        let notification = NotificationMessage::new_data_change(sequence_number, DateTime::now(), monitored_item_notifications);
        session.subscriptions.retransmission_queue().insert(sequence_number, (subscription_id, notification));
    }

    // try for a notification message known to exist
    let request = RepublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id,
        retransmit_sequence_number: sequence_number,
    };
    let response = ss.republish(&mut session, request).unwrap();
    trace!("republish response {:#?}", response);
    let response: RepublishResponse = supported_message_as!(response, RepublishResponse);
    assert_eq!(response.notification_message.sequence_number, sequence_number);

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
        subscription_id: subscription_id,
        retransmit_sequence_number: sequence_number + 1,
    };
    let response: ServiceFault = supported_message_as!(ss.republish(&mut session, request).unwrap(), ServiceFault);
    assert_eq!(response.response_header.service_result, StatusCode::BadMessageNotAvailable);
}