use std::collections::HashSet;
use std::ops::Add;

use chrono::{self, Utc};

use super::*;
use crate::server::{
    services::{monitored_item::MonitoredItemService, subscription::SubscriptionService},
    subscriptions::{
        monitored_item::*,
        subscription::{SubscriptionState, TickReason},
    },
};
use crate::supported_message_as;

fn test_var_node_id() -> NodeId {
    NodeId::new(1, 1)
}

fn test_object_node_id() -> NodeId {
    NodeId::new(1, 1000)
}

fn make_address_space() -> AddressSpace {
    let mut address_space = AddressSpace::new();

    (1..=5).for_each(|i| {
        let id = format!("test{}", i);
        VariableBuilder::new(&NodeId::new(1, i), &id, &id)
            .data_type(DataTypeId::UInt32)
            .value(0u32)
            .organized_by(ObjectId::ObjectsFolder)
            .insert(&mut address_space);
    });

    // An object for event filter
    ObjectBuilder::new(&test_object_node_id(), "Object1", "")
        .organized_by(ObjectId::ObjectsFolder)
        .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
        .insert(&mut address_space);

    address_space
}

fn make_create_request(
    sampling_interval: Duration,
    queue_size: u32,
    node_id: NodeId,
    attribute_id: AttributeId,
    filter: ExtensionObject,
) -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest {
        item_to_monitor: ReadValueId {
            node_id,
            attribute_id: attribute_id as u32,
            index_range: UAString::null(),
            data_encoding: QualifiedName::null(),
        },
        monitoring_mode: MonitoringMode::Reporting,
        requested_parameters: MonitoringParameters {
            client_handle: 999,
            sampling_interval,
            filter,
            queue_size,
            discard_oldest: true,
        },
    }
}

fn make_create_request_data_change_filter(
    sampling_interval: Duration,
    queue_size: u32,
) -> MonitoredItemCreateRequest {
    // Encode a filter to an extension object
    let filter = ExtensionObject::from_encodable(
        ObjectId::DataChangeFilter_Encoding_DefaultBinary,
        &DataChangeFilter {
            trigger: DataChangeTrigger::StatusValueTimestamp,
            deadband_type: DeadbandType::None as u32,
            deadband_value: 0f64,
        },
    );
    make_create_request(
        sampling_interval,
        queue_size,
        test_var_node_id(),
        AttributeId::Value,
        filter,
    )
}

fn make_create_request_event_filter(
    sampling_interval: Duration,
    queue_size: u32,
) -> MonitoredItemCreateRequest {
    let filter = ExtensionObject::from_encodable(
        ObjectId::EventFilter_Encoding_DefaultBinary,
        &EventFilter {
            where_clause: ContentFilter { elements: None },
            select_clauses: Some(vec![
                SimpleAttributeOperand::new(
                    ObjectTypeId::BaseEventType,
                    "EventId",
                    AttributeId::Value,
                    UAString::null(),
                ),
                SimpleAttributeOperand::new(
                    ObjectTypeId::BaseEventType,
                    "SourceNode",
                    AttributeId::Value,
                    UAString::null(),
                ),
            ]),
        },
    );
    make_create_request(
        sampling_interval,
        queue_size,
        test_object_node_id(),
        AttributeId::EventNotifier,
        filter,
    )
}

fn set_monitoring_mode(
    session: Arc<RwLock<Session>>,
    subscription_id: u32,
    monitored_item_id: u32,
    monitoring_mode: MonitoringMode,
    mis: &MonitoredItemService,
) {
    let request = SetMonitoringModeRequest {
        request_header: RequestHeader::dummy(),
        subscription_id,
        monitoring_mode,
        monitored_item_ids: Some(vec![monitored_item_id]),
    };
    let response: SetMonitoringModeResponse = supported_message_as!(
        mis.set_monitoring_mode(session, &request),
        SetMonitoringModeResponse
    );
    let results = response.results.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], StatusCode::Good);
}

fn set_triggering(
    session: Arc<RwLock<Session>>,
    subscription_id: u32,
    monitored_item_id: u32,
    links_to_add: &[u32],
    links_to_remove: &[u32],
    mis: &MonitoredItemService,
) -> (Option<Vec<StatusCode>>, Option<Vec<StatusCode>>) {
    let request = SetTriggeringRequest {
        request_header: RequestHeader::dummy(),
        subscription_id,
        triggering_item_id: monitored_item_id,
        links_to_add: if links_to_add.is_empty() {
            None
        } else {
            Some(links_to_add.to_vec())
        },
        links_to_remove: if links_to_remove.is_empty() {
            None
        } else {
            Some(links_to_remove.to_vec())
        },
    };
    let response: SetTriggeringResponse =
        supported_message_as!(mis.set_triggering(session, &request), SetTriggeringResponse);
    (response.add_results, response.remove_results)
}

fn publish_request(
    now: &DateTimeUtc,
    session: Arc<RwLock<Session>>,
    address_space: Arc<RwLock<AddressSpace>>,
    ss: &SubscriptionService,
) {
    let request_id = 1001;
    let request = PublishRequest {
        request_header: RequestHeader::dummy(),
        subscription_acknowledgements: None,
    };

    {
        let mut session = trace_write_lock!(session);
        session.subscriptions_mut().publish_request_queue().clear();
    }

    let response = ss.async_publish(
        now,
        session.clone(),
        address_space.clone(),
        request_id,
        &request,
    );
    assert!(response.is_none());

    let mut session = trace_write_lock!(session);
    assert!(!session
        .subscriptions_mut()
        .publish_request_queue()
        .is_empty());
}

fn publish_response(session: Arc<RwLock<Session>>) -> PublishResponse {
    let mut session = trace_write_lock!(session);
    let response = session
        .subscriptions_mut()
        .publish_response_queue()
        .pop_back()
        .unwrap()
        .response;
    let response: PublishResponse = supported_message_as!(response, PublishResponse);
    response
}

fn publish_tick_no_response(
    session: Arc<RwLock<Session>>,
    ss: &SubscriptionService,
    address_space: Arc<RwLock<AddressSpace>>,
    now: DateTimeUtc,
    duration: chrono::Duration,
) -> DateTimeUtc {
    publish_request(&now, session.clone(), address_space.clone(), ss);
    let now = now.add(duration);
    let mut session = trace_write_lock!(session);
    let address_space = trace_read_lock!(address_space);
    let _ = session.tick_subscriptions(&now, &address_space, TickReason::TickTimerFired);
    assert_eq!(
        session.subscriptions_mut().publish_response_queue().len(),
        0
    );
    now
}

/// Does a publish, ticks by a duration and then calls the function to handle the response. The
/// new timestamp is returned so it can be called again.
fn publish_tick_response<T>(
    session: Arc<RwLock<Session>>,
    ss: &SubscriptionService,
    address_space: Arc<RwLock<AddressSpace>>,
    now: DateTimeUtc,
    duration: chrono::Duration,
    handler: T,
) -> DateTimeUtc
where
    T: FnOnce(PublishResponse),
{
    publish_request(&now, session.clone(), address_space.clone(), ss);
    let now = now.add(duration);
    {
        let mut session = trace_write_lock!(session);
        let address_space = trace_read_lock!(address_space);
        let _ = session.tick_subscriptions(&now, &address_space, TickReason::TickTimerFired);
        assert_eq!(
            session.subscriptions_mut().publish_response_queue().len(),
            1
        );
    }
    let response = publish_response(session.clone());
    handler(response);
    now
}

fn populate_monitored_item(server_state: &ServerState, discard_oldest: bool) -> MonitoredItem {
    let client_handle = 999;
    let mut monitored_item = MonitoredItem::new(
        &chrono::Utc::now(),
        1,
        TimestampsToReturn::Both,
        server_state,
        &make_create_request_data_change_filter(-1f64, 5),
    )
    .unwrap();
    monitored_item.set_discard_oldest(discard_oldest);
    for i in 0..5 {
        monitored_item.enqueue_notification_message(MonitoredItemNotification {
            client_handle,
            value: DataValue::new_now(i as i32),
        });
        assert!(!monitored_item.queue_overflow());
    }

    monitored_item.enqueue_notification_message(MonitoredItemNotification {
        client_handle,
        value: DataValue::new_now(10 as i32),
    });
    assert!(monitored_item.queue_overflow());
    monitored_item
}

fn assert_first_notification_is_i32(monitored_item: &mut MonitoredItem, value: i32) {
    let notification = monitored_item.oldest_notification_message().unwrap();
    if let Notification::MonitoredItemNotification(notification) = notification {
        assert_eq!(notification.value.value.unwrap(), Variant::Int32(value));
    } else {
        panic!();
    }
}

#[test]
fn data_change_filter_test() {
    let mut filter = DataChangeFilter {
        trigger: DataChangeTrigger::Status,
        deadband_type: DeadbandType::None as u32,
        deadband_value: 0f64,
    };

    let mut v1 = DataValue {
        value: None,
        status: None,
        source_timestamp: None,
        source_picoseconds: None,
        server_timestamp: None,
        server_picoseconds: None,
    };

    let mut v2 = DataValue {
        value: None,
        status: None,
        source_timestamp: None,
        source_picoseconds: None,
        server_timestamp: None,
        server_picoseconds: None,
    };

    assert_eq!(filter.compare(&v1, &v2, None), true);

    // Change v1 status
    v1.status = Some(StatusCode::Good);
    assert_eq!(filter.compare(&v1, &v2, None), false);

    // Change v2 status
    v2.status = Some(StatusCode::Good);
    assert_eq!(filter.compare(&v1, &v2, None), true);

    // Change value - but since trigger is status, this should not matter
    v1.value = Some(Variant::Boolean(true));
    assert_eq!(filter.compare(&v1, &v2, None), true);

    // Change trigger to status-value and change should matter
    filter.trigger = DataChangeTrigger::StatusValue;
    assert_eq!(filter.compare(&v1, &v2, None), false);

    // Now values are the same
    v2.value = Some(Variant::Boolean(true));
    assert_eq!(filter.compare(&v1, &v2, None), true);

    // And for status-value-timestamp
    filter.trigger = DataChangeTrigger::StatusValueTimestamp;
    assert_eq!(filter.compare(&v1, &v2, None), true);

    // Change timestamps to differ
    let now = DateTime::now();
    v1.server_timestamp = Some(now.clone());
    assert_eq!(filter.compare(&v1, &v2, None), false);
}

#[test]
fn data_change_deadband_abs_test() {
    let filter = DataChangeFilter {
        trigger: DataChangeTrigger::StatusValue,
        // Abs compare
        deadband_type: DeadbandType::Absolute as u32,
        deadband_value: 1f64,
    };

    let v1 = DataValue {
        value: Some(Variant::Double(10f64)),
        status: None,
        source_timestamp: None,
        source_picoseconds: None,
        server_timestamp: None,
        server_picoseconds: None,
    };

    let mut v2 = DataValue {
        value: Some(Variant::Double(10f64)),
        status: None,
        source_timestamp: None,
        source_picoseconds: None,
        server_timestamp: None,
        server_picoseconds: None,
    };

    // Values are the same so deadband should not matter
    assert_eq!(filter.compare(&v1, &v2, None), true);

    // Adjust by less than deadband
    v2.value = Some(Variant::Double(10.9f64));
    assert_eq!(filter.compare(&v1, &v2, None), true);

    // Adjust by equal deadband
    v2.value = Some(Variant::Double(11f64));
    assert_eq!(filter.compare(&v1, &v2, None), true);

    // Adjust by equal deadband plus a little bit
    v2.value = Some(Variant::Double(11.00001f64));
    assert_eq!(filter.compare(&v1, &v2, None), false);
}

// Straight tests of abs function
#[test]
fn deadband_abs() {
    assert_eq!(DataChangeFilter::abs_compare(100f64, 100f64, 0f64), true);
    assert_eq!(DataChangeFilter::abs_compare(100f64, 100f64, 1f64), true);
    assert_eq!(DataChangeFilter::abs_compare(100f64, 101f64, 1f64), true);
    assert_eq!(DataChangeFilter::abs_compare(101f64, 100f64, 1f64), true);
    assert_eq!(
        DataChangeFilter::abs_compare(101.001f64, 100f64, 1f64),
        false
    );
    assert_eq!(
        DataChangeFilter::abs_compare(100f64, 101.001f64, 1f64),
        false
    );
}

// Straight tests of pct function
#[test]
fn deadband_pct() {
    assert_eq!(
        DataChangeFilter::pct_compare(100f64, 101f64, 0f64, 100f64, 0f64),
        false
    );
    assert_eq!(
        DataChangeFilter::pct_compare(100f64, 101f64, 0f64, 100f64, 1f64),
        true
    );
    assert_eq!(
        DataChangeFilter::pct_compare(100f64, 101.0001f64, 0f64, 100f64, 1f64),
        false
    );
    assert_eq!(
        DataChangeFilter::pct_compare(101.0001f64, 100f64, 0f64, 100f64, 1f64),
        false
    );
    assert_eq!(
        DataChangeFilter::pct_compare(101.0001f64, 100f64, 0f64, 100f64, 1.0002f64),
        true
    );
}

#[test]
fn monitored_item_data_change_filter() {
    // create an address space
    do_subscription_service_test(
        |server_state,
         _session,
         _address_space,
         _ss: SubscriptionService,
         _mis: MonitoredItemService| {
            let mut address_space = make_address_space();
            let server_state = trace_read_lock!(server_state);

            // Create request should monitor attribute of variable, e.g. value
            // Sample interval is negative so it will always test on repeated calls
            let mut monitored_item = MonitoredItem::new(
                &chrono::Utc::now(),
                1,
                TimestampsToReturn::Both,
                &server_state,
                &make_create_request_data_change_filter(-1f64, 5),
            )
            .unwrap();

            let now = Utc::now();

            assert_eq!(monitored_item.notification_queue().len(), 0);

            // Expect first call to always succeed
            assert_eq!(
                monitored_item.tick(&now, &address_space, true, false),
                TickResult::ReportValueChanged
            );

            // Expect one item in its queue
            assert_eq!(monitored_item.notification_queue().len(), 1);

            // Expect false on next tick, with the same value because no subscription timer has fired
            assert_eq!(
                monitored_item.tick(&now, &address_space, false, false),
                TickResult::NoChange
            );
            assert_eq!(monitored_item.notification_queue().len(), 1);

            // Expect false because publish timer elapses but value has not changed changed
            assert_eq!(
                monitored_item.tick(&now, &address_space, false, false),
                TickResult::NoChange
            );
            assert_eq!(monitored_item.notification_queue().len(), 1);

            // adjust variable value
            if let &mut NodeType::Variable(ref mut node) =
                address_space.find_node_mut(&test_var_node_id()).unwrap()
            {
                let _ = node
                    .set_value(NumericRange::None, Variant::UInt32(1))
                    .unwrap();
            } else {
                panic!("Expected a variable, didn't get one!!");
            }

            // Expect change but only when subscription timer elapsed
            assert_eq!(
                monitored_item.tick(&now, &address_space, false, false),
                TickResult::NoChange
            );
            assert_eq!(
                monitored_item.tick(&now, &address_space, true, false),
                TickResult::ReportValueChanged
            );
            assert_eq!(monitored_item.notification_queue().len(), 2);
        },
    )
}

#[test]
fn monitored_item_event_filter() {
    // create an address space
    do_subscription_service_test(
        |server_state,
         _session,
         _address_space,
         _ss: SubscriptionService,
         _mis: MonitoredItemService| {
            let mut address_space = make_address_space();
            let server_state = trace_read_lock!(server_state);

            let ns = address_space.register_namespace("urn:test").unwrap();

            // Create request should monitor attribute of variable, e.g. value
            // Sample interval is negative so it will always test on repeated calls
            let mut monitored_item = MonitoredItem::new(
                &chrono::Utc::now(),
                1,
                TimestampsToReturn::Both,
                &server_state,
                &make_create_request_event_filter(-1f64, 5),
            )
            .unwrap();

            let mut now = Utc::now();

            // Verify tick does nothing
            assert_eq!(
                monitored_item.tick(&now, &address_space, false, false),
                TickResult::NoChange
            );

            now = now + chrono::Duration::milliseconds(100);

            // Raise an event
            let event_id = NodeId::new(ns, "Event1");
            let event_type_id = ObjectTypeId::BaseEventType;
            let mut event = BaseEventType::new(
                &event_id,
                event_type_id,
                "Event1",
                "",
                NodeId::objects_folder_id(),
                DateTime::from(now),
            )
            .source_node(test_object_node_id());
            assert!(event.raise(&mut address_space).is_ok());

            // Verify that event comes back
            assert_eq!(
                monitored_item.tick(&now, &address_space, true, false),
                TickResult::ReportValueChanged
            );

            // Look at monitored item queue
            assert_eq!(monitored_item.notification_queue().len(), 1);
            let event = match monitored_item.oldest_notification_message().unwrap() {
                Notification::Event(event) => event,
                _ => panic!(),
            };

            // Verify EventFieldList
            assert_eq!(event.client_handle, 999);
            let mut event_fields = event.event_fields.unwrap();
            assert_eq!(event_fields.len(), 2);

            // EventId should be a ByteString, contents of which should be 16 bytes
            let event_id = event_fields.remove(0);
            match event_id {
                Variant::ByteString(value) => assert_eq!(value.value.unwrap().len(), 16),
                _ => panic!(),
            }

            // Source node should point to the originating object
            let event_source_node = event_fields.remove(0);
            match event_source_node {
                Variant::NodeId(source_node) => assert_eq!(*source_node, test_object_node_id()),
                _ => panic!(),
            }

            // Tick again (nothing expected)
            now = now + chrono::Duration::milliseconds(100);
            assert_eq!(
                monitored_item.tick(&now, &address_space, false, false),
                TickResult::NoChange
            );

            // Raise an event on another object, expect nothing in the tick about it
            let event_id = NodeId::new(ns, "Event2");
            let event_type_id = ObjectTypeId::BaseEventType;
            let mut event = BaseEventType::new(
                &event_id,
                event_type_id,
                "Event2",
                "",
                NodeId::objects_folder_id(),
                DateTime::from(now),
            )
            .source_node(ObjectId::Server);
            assert!(event.raise(&mut address_space).is_ok());
            now = now + chrono::Duration::milliseconds(100);
            assert_eq!(
                monitored_item.tick(&now, &address_space, false, false),
                TickResult::NoChange
            );
        },
    );
}

/// Test to ensure create monitored items returns an error for an unknown node id
#[test]
fn unknown_node_id() {
    do_subscription_service_test(
        |server_state,
         session,
         address_space,
         ss: SubscriptionService,
         mis: MonitoredItemService| {
            // Create subscription
            let subscription_id = {
                let request = create_subscription_request(0, 0);
                let response: CreateSubscriptionResponse = supported_message_as!(
                    ss.create_subscription(server_state.clone(), session.clone(), &request),
                    CreateSubscriptionResponse
                );
                response.subscription_id
            };

            let request = create_monitored_items_request(
                subscription_id,
                vec![
                    NodeId::new(1, var_name(1)),
                    NodeId::new(99, "Doesn't exist"),
                ],
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
            let results = response.results.unwrap();
            assert_eq!(results.len(), 2);
            assert_eq!(
                results.get(0).as_ref().unwrap().status_code,
                StatusCode::Good
            );
            assert_eq!(
                results.get(1).as_ref().unwrap().status_code,
                StatusCode::BadNodeIdUnknown
            );
        },
    );
}

#[test]
fn monitored_item_triggers() {
    do_subscription_service_test(
        |server_state,
         session,
         address_space,
         ss: SubscriptionService,
         mis: MonitoredItemService| {
            // Create subscription
            let subscription_id = {
                let request = create_subscription_request(0, 0);
                let response: CreateSubscriptionResponse = supported_message_as!(
                    ss.create_subscription(server_state.clone(), session.clone(), &request),
                    CreateSubscriptionResponse
                );
                response.subscription_id
            };

            {
                let mut session = trace_write_lock!(session);
                session
                    .subscriptions_mut()
                    .get_mut(subscription_id)
                    .unwrap()
                    .set_state(SubscriptionState::Normal);
            }

            let max_monitored_items: usize = 4;

            let triggering_node = NodeId::new(1, var_name(0));
            // create 4 monitored items
            let request = create_monitored_items_request(
                subscription_id,
                vec![
                    triggering_node.clone(),
                    NodeId::new(1, var_name(1)),
                    NodeId::new(1, var_name(2)),
                    NodeId::new(1, var_name(3)),
                ],
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

            // The first monitored item will be the triggering item, the other 3 will be triggered items
            let monitored_item_ids: Vec<u32> = response
                .results
                .unwrap()
                .iter()
                .map(|mir| {
                    assert_eq!(mir.status_code, StatusCode::Good);
                    mir.monitored_item_id
                })
                .collect();
            assert_eq!(monitored_item_ids.len(), max_monitored_items);

            let triggering_item_id = monitored_item_ids[0];
            let triggered_item_ids = &monitored_item_ids[1..];

            // set 3 monitored items to be reporting, sampling, disabled respectively
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[0],
                MonitoringMode::Reporting,
                &mis,
            );
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[1],
                MonitoringMode::Sampling,
                &mis,
            );
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[2],
                MonitoringMode::Disabled,
                &mis,
            );

            // set 1 monitored item to trigger other 3 plus itself
            let (add_results, remove_results) = set_triggering(
                session.clone(),
                subscription_id,
                monitored_item_ids[0],
                &[
                    monitored_item_ids[0],
                    monitored_item_ids[1],
                    monitored_item_ids[2],
                    monitored_item_ids[3],
                ],
                &[],
                &mis,
            );

            // expect all adds to succeed except the one to itself
            assert!(remove_results.is_none());
            let add_results = add_results.unwrap();
            assert_eq!(add_results[0], StatusCode::BadMonitoredItemIdInvalid);
            assert_eq!(add_results[1], StatusCode::Good);
            assert_eq!(add_results[2], StatusCode::Good);
            assert_eq!(add_results[3], StatusCode::Good);

            let now = Utc::now();

            // publish on the monitored item
            let now = publish_tick_response(
                session.clone(),
                &ss,
                address_space.clone(),
                now,
                chrono::Duration::seconds(2),
                |response| {
                    let (notifications, events) = response
                        .notification_message
                        .notifications(&DecodingOptions::test())
                        .unwrap();
                    assert_eq!(notifications.len(), 1);
                    assert!(events.is_empty());
                    let monitored_items = notifications[0].monitored_items.as_ref().unwrap();
                    assert_eq!(monitored_items.len(), 3);
                    let client_handles: HashSet<u32> = monitored_items
                        .iter()
                        .map(|min| min.client_handle)
                        .collect();
                    // expect a notification to be for triggering item
                    assert!(client_handles.contains(&0));
                    // expect a notification to be for triggered[0] (reporting) because it's reporting
                    assert!(client_handles.contains(&1));
                    // expect a notification to be for triggered[1] (sampling)
                    assert!(client_handles.contains(&2));
                },
            );

            // do a publish on the monitored item, expect no notification because nothing has changed
            let now = publish_tick_no_response(
                session.clone(),
                &ss,
                address_space.clone(),
                now,
                chrono::Duration::seconds(2),
            );

            // set monitoring mode of all 3 to reporting.
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[0],
                MonitoringMode::Reporting,
                &mis,
            );
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[1],
                MonitoringMode::Reporting,
                &mis,
            );
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[2],
                MonitoringMode::Reporting,
                &mis,
            );

            // Change the triggering item's value
            {
                let mut address_space = trace_write_lock!(address_space);
                let _ = address_space.set_variable_value(
                    triggering_node.clone(),
                    1,
                    &DateTime::from(now.clone()),
                    &DateTime::from(now.clone()),
                );
            }

            // In this case, the triggering item changes, but triggered items are all reporting so are ignored unless they themselves
            // need to report. Only 3 will fire because it was disabled previously
            let now = publish_tick_response(
                session.clone(),
                &ss,
                address_space.clone(),
                now,
                chrono::Duration::seconds(2),
                |response| {
                    let (notifications, events) = response
                        .notification_message
                        .notifications(&DecodingOptions::test())
                        .unwrap();
                    assert_eq!(notifications.len(), 1);
                    assert!(events.is_empty());
                    let monitored_items = notifications[0].monitored_items.as_ref().unwrap();
                    let client_handles: HashSet<u32> = monitored_items
                        .iter()
                        .map(|min| min.client_handle)
                        .collect();
                    assert_eq!(monitored_items.len(), 2);
                    assert!(client_handles.contains(&0));
                    assert!(client_handles.contains(&3));
                },
            );

            // revert to 3 items to be reporting, sampling, disabled
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[0],
                MonitoringMode::Reporting,
                &mis,
            );
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[1],
                MonitoringMode::Sampling,
                &mis,
            );
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggered_item_ids[2],
                MonitoringMode::Disabled,
                &mis,
            );

            // change monitoring mode of triggering item to sampling and change value
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggering_item_id,
                MonitoringMode::Sampling,
                &mis,
            );
            {
                let mut address_space = trace_write_lock!(address_space);
                let _ = address_space.set_variable_value(
                    triggering_node.clone(),
                    2,
                    &DateTime::from(now.clone()),
                    &DateTime::from(now.clone()),
                );
            }

            // do a publish on the monitored item,
            let now = publish_tick_response(
                session.clone(),
                &ss,
                address_space.clone(),
                now,
                chrono::Duration::seconds(2),
                |response| {
                    // expect only 1 data change corresponding to sampling triggered item
                    let (notifications, events) = response
                        .notification_message
                        .notifications(&DecodingOptions::test())
                        .unwrap();
                    assert_eq!(notifications.len(), 1);
                    assert!(events.is_empty());
                    let monitored_items = notifications[0].monitored_items.as_ref().unwrap();
                    let client_handles: HashSet<u32> = monitored_items
                        .iter()
                        .map(|min| min.client_handle)
                        .collect();
                    assert_eq!(monitored_items.len(), 1);
                    assert!(client_handles.contains(&2));
                },
            );

            // change monitoring mode of triggering item to disable
            set_monitoring_mode(
                session.clone(),
                subscription_id,
                triggering_item_id,
                MonitoringMode::Disabled,
                &mis,
            );
            {
                let mut address_space = trace_write_lock!(address_space);
                let _ = address_space.set_variable_value(
                    triggering_node.clone(),
                    3,
                    &DateTime::from(now.clone()),
                    &DateTime::from(now.clone()),
                );
            }

            // do a publish on the monitored item, expect 0 data changes
            let _ = publish_tick_no_response(
                session.clone(),
                &ss,
                address_space.clone(),
                now,
                chrono::Duration::seconds(2),
            );
        },
    );
}

#[test]
fn monitored_item_queue_discard_oldest() {
    // The purpose of this test is to monitor the discard oldest behaviour. Depending on true/false
    // the oldest or newest item will be overwritten when the queue is full

    do_subscription_service_test(
        |server_state,
         _session,
         _address_space,
         _ss: SubscriptionService,
         _mis: MonitoredItemService| {
            let server_state = trace_read_lock!(server_state);

            // discard_oldest = true
            {
                let mut monitored_item = populate_monitored_item(&server_state, true);
                assert_first_notification_is_i32(&mut monitored_item, 1);
                assert_first_notification_is_i32(&mut monitored_item, 2);
                assert_first_notification_is_i32(&mut monitored_item, 3);
                assert_first_notification_is_i32(&mut monitored_item, 4);
                assert_first_notification_is_i32(&mut monitored_item, 10);
            }

            // discard_oldest = false
            {
                let mut monitored_item = populate_monitored_item(&server_state, false);
                assert_first_notification_is_i32(&mut monitored_item, 0);
                assert_first_notification_is_i32(&mut monitored_item, 1);
                assert_first_notification_is_i32(&mut monitored_item, 2);
                assert_first_notification_is_i32(&mut monitored_item, 3);
                assert_first_notification_is_i32(&mut monitored_item, 10);
            }
        },
    );
}
