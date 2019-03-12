use std::ops::Add;

use chrono::{self, Utc};

use crate::{
    prelude::*,
    subscriptions::subscription::{TickReason, SubscriptionState},
    subscriptions::monitored_item::*,
    services::{
        subscription::SubscriptionService,
        monitored_item::MonitoredItemService,
    },
    DateTimeUtc,
};
use super::*;

fn test_var_node_id() -> NodeId {
    NodeId::new(1, 1)
}

fn make_address_space() -> AddressSpace {
    let mut address_space = AddressSpace::new();
    let _ = address_space.add_variable(Variable::new(&NodeId::new(1, 1), "test1", "test1", "", 0u32), &AddressSpace::objects_folder_id());
    let _ = address_space.add_variable(Variable::new(&NodeId::new(1, 2), "test2", "test2", "", 0u32), &AddressSpace::objects_folder_id());
    let _ = address_space.add_variable(Variable::new(&NodeId::new(1, 3), "test3", "test3", "", 0u32), &AddressSpace::objects_folder_id());
    let _ = address_space.add_variable(Variable::new(&NodeId::new(1, 4), "test4", "test4", "", 0u32), &AddressSpace::objects_folder_id());
    let _ = address_space.add_variable(Variable::new(&NodeId::new(1, 5), "test5", "test5 ", "", 0u32), &AddressSpace::objects_folder_id());
    address_space
}

fn make_create_request(sampling_interval: Duration, queue_size: u32) -> MonitoredItemCreateRequest {
    // Encode a filter to an extension object
    let filter = ExtensionObject::from_encodable(ObjectId::DataChangeFilter_Encoding_DefaultBinary, &DataChangeFilter {
        trigger: DataChangeTrigger::StatusValueTimestamp,
        deadband_type: 0,
        deadband_value: 0f64,
    });

    MonitoredItemCreateRequest {
        item_to_monitor: ReadValueId {
            node_id: test_var_node_id(),
            attribute_id: AttributeId::Value as u32,
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

fn set_monitoring_mode(session: &mut Session, subscription_id: u32, monitored_item_id: u32, monitoring_mode: MonitoringMode, mis: &MonitoredItemService) {
    let request = SetMonitoringModeRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id,
        monitoring_mode,
        monitored_item_ids: Some(vec![monitored_item_id]),
    };
    let response: SetMonitoringModeResponse = supported_message_as!(mis.set_monitoring_mode(session, &request).unwrap(), SetMonitoringModeResponse);
    let results = response.results.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], StatusCode::Good);
}

fn set_triggering(session: &mut Session, subscription_id: u32, monitored_item_id: u32, links_to_add: &[u32], links_to_remove: &[u32], mis: &MonitoredItemService) -> (Option<Vec<StatusCode>>, Option<Vec<StatusCode>>) {
    let request = SetTriggeringRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_id,
        triggering_item_id: monitored_item_id,
        links_to_add: if links_to_add.is_empty() { None } else { Some(links_to_add.to_vec()) },
        links_to_remove: if links_to_remove.is_empty() { None } else { Some(links_to_remove.to_vec()) },
    };
    let response: SetTriggeringResponse = supported_message_as!(mis.set_triggering(session, &request).unwrap(), SetTriggeringResponse);
    (response.add_results, response.remove_results)
}

fn publish_request(session: &mut Session, ss: &SubscriptionService) {
    let request_id = 1001;
    let request = PublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_acknowledgements: None,
    };
//    assert!(session.subscriptions.publish_request_queue.is_empty());
    let response = ss.async_publish(session, request_id, &request).unwrap();
//    assert!(response.is_none());
//    assert!(!session.subscriptions.publish_request_queue.is_empty());
}

fn publish_response(session: &mut Session) -> PublishResponse {
    let response = session.subscriptions.publish_response_queue.pop_back().unwrap().response;
    let response: PublishResponse = supported_message_as!(response, PublishResponse);
    response
}

/// Does a publish, ticks by a duration and then calls the function to handle the response. The
/// new timestamp is returned so it can be called again.
fn publish_tick_response<T>(session: &mut Session, ss: &SubscriptionService, address_space: &AddressSpace, now: DateTimeUtc, duration: chrono::Duration, handler: T) -> DateTimeUtc
    where T: FnOnce(PublishResponse)
{
    publish_request(session, ss);
    let now = now.add(duration);
    let _ = session.tick_subscriptions(&now, address_space, TickReason::TickTimerFired);
//    assert_eq!(session.subscriptions.publish_response_queue.len(), 1);
//    let response = publish_response(session);
//    handler(response);
    now
}

fn populate_monitored_item(discard_oldest: bool) -> MonitoredItem {
    let client_handle = 999;
    let mut monitored_item = MonitoredItem::new(1, TimestampsToReturn::Both, &make_create_request(-1f64, 5)).unwrap();
    monitored_item.set_discard_oldest(discard_oldest);
    for i in 0..5 {
        monitored_item.enqueue_notification_message(MonitoredItemNotification {
            client_handle,
            value: DataValue::new(i as i32),
        });
        assert!(!monitored_item.queue_overflow());
    }

    monitored_item.enqueue_notification_message(MonitoredItemNotification {
        client_handle,
        value: DataValue::new(10 as i32),
    });
    assert!(monitored_item.queue_overflow());
    monitored_item
}

fn assert_first_notification_is_i32(monitored_item: &mut MonitoredItem, value: i32) {
    assert_eq!(monitored_item.oldest_notification_message().unwrap().value.value.unwrap(), Variant::Int32(value));
}

#[test]
fn data_change_filter_test() {
    let mut filter = DataChangeFilter {
        trigger: DataChangeTrigger::Status,
        deadband_type: 0,
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
    v1.status = Some(StatusCode::Good.bits());
    assert_eq!(filter.compare(&v1, &v2, None), false);

    // Change v2 status
    v2.status = Some(StatusCode::Good.bits());
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
        deadband_type: 1,
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
    assert_eq!(DataChangeFilter::abs_compare(101.001f64, 100f64, 1f64), false);
    assert_eq!(DataChangeFilter::abs_compare(100f64, 101.001f64, 1f64), false);
}

// Straight tests of pct function
#[test]
fn deadband_pct() {
    assert_eq!(DataChangeFilter::pct_compare(100f64, 101f64, 0f64, 100f64, 0f64), false);
    assert_eq!(DataChangeFilter::pct_compare(100f64, 101f64, 0f64, 100f64, 1f64), true);
    assert_eq!(DataChangeFilter::pct_compare(100f64, 101.0001f64, 0f64, 100f64, 1f64), false);
    assert_eq!(DataChangeFilter::pct_compare(101.0001f64, 100f64, 0f64, 100f64, 1f64), false);
    assert_eq!(DataChangeFilter::pct_compare(101.0001f64, 100f64, 0f64, 100f64, 1.0002f64), true);
}

#[test]
fn monitored_item_data_change_filter() {
    // create an address space
    let mut address_space = make_address_space();

    // Create request should monitor attribute of variable, e.g. value
    // Sample interval is negative so it will always test on repeated calls
    let mut monitored_item = MonitoredItem::new(1, TimestampsToReturn::Both, &make_create_request(-1f64, 5)).unwrap();

    let now = Utc::now();

    assert_eq!(monitored_item.notification_queue().len(), 0);

    // Expect first call to always succeed
    assert_eq!(monitored_item.tick(&address_space, &now, false, false), TickResult::ReportValueChanged);

    // Expect one item in its queue
    assert_eq!(monitored_item.notification_queue().len(), 1);

    // Expect false on next tick, with the same value because no subscription timer has fired
    assert_eq!(monitored_item.tick(&address_space, &now, false, false), TickResult::NoChange);
    assert_eq!(monitored_item.notification_queue().len(), 1);

    // adjust variable value
    if let &mut NodeType::Variable(ref mut node) = address_space.find_node_mut(&test_var_node_id()).unwrap() {
        let mut value = node.value();
        value.value = Some(Variant::UInt32(1));
        node.set_value(value);
    } else {
        panic!("Expected a variable, didn't get one!!");
    }

    // Expect change but only when subscription timer elapsed
    assert_eq!(monitored_item.tick(&address_space, &now, false, false), TickResult::NoChange);
    assert_eq!(monitored_item.tick(&address_space, &now, true, false), TickResult::ReportValueChanged);
    assert_eq!(monitored_item.notification_queue().len(), 2);
}

#[test]
fn monitored_item_triggers() {
    do_subscription_service_test(|server_state, session, address_space, ss: SubscriptionService, mis: MonitoredItemService| {
        // Create subscription
        let subscription_id = {
            let request = create_subscription_request(0, 0);
            let response: CreateSubscriptionResponse = supported_message_as!(ss.create_subscription(server_state, session, &request).unwrap(), CreateSubscriptionResponse);
            response.subscription_id
        };
        session.subscriptions.get_mut(subscription_id).unwrap().set_state(SubscriptionState::Normal);

        let max_monitored_items: usize = 4;

        // create 4 monitored items
        let request = create_monitored_items_request(subscription_id, vec![
            NodeId::new(1, 1),
            NodeId::new(1, 2),
            NodeId::new(1, 3),
            NodeId::new(1, 4),
        ]);
        let response: CreateMonitoredItemsResponse = supported_message_as!(mis.create_monitored_items(session, &request).unwrap(), CreateMonitoredItemsResponse);

        // The first monitored item will be the triggering item, the other 3 will be triggered items
        let monitored_item_ids: Vec<u32> = response.results.unwrap().iter().map(|mir| {
            assert_eq!(mir.status_code, StatusCode::Good);
            mir.monitored_item_id
        }).collect();
        assert_eq!(monitored_item_ids.len(), max_monitored_items);

        let triggering_item_id = monitored_item_ids[0];
        let triggered_item_ids = &monitored_item_ids[1..];

        // set 3 monitored items to be reporting, sampling, disabled respectively
        set_monitoring_mode(session, subscription_id, triggered_item_ids[0], MonitoringMode::Reporting, &mis);
        set_monitoring_mode(session, subscription_id, triggered_item_ids[1], MonitoringMode::Sampling, &mis);
        set_monitoring_mode(session, subscription_id, triggered_item_ids[2], MonitoringMode::Disabled, &mis);

        // set 1 monitored item to trigger other 3 plus itself
        let (add_results, remove_results) = set_triggering(session, subscription_id, monitored_item_ids[0], &[monitored_item_ids[0], monitored_item_ids[1], monitored_item_ids[2], monitored_item_ids[3]], &[], &mis);

        // expect all adds to succeed except the one to itself
        assert!(remove_results.is_none());
        let add_results = add_results.unwrap();
        assert_eq!(add_results[0], StatusCode::BadMonitoredItemIdInvalid);
        assert_eq!(add_results[1], StatusCode::Good);
        assert_eq!(add_results[2], StatusCode::Good);
        assert_eq!(add_results[3], StatusCode::Good);

        let now = Utc::now();

        // publish on the monitored item
        let now = publish_tick_response(session, &ss, address_space, now, chrono::Duration::seconds(2), |response| {
            let notifications = response.notification_message.data_change_notifications(&DecodingLimits::default());
            // assert_eq!(notifications.len(), 2);
            // TODO expect a notification to be for triggering item
            // TODO expect a notification to be for triggered idx 1 (sampling)
        });

        // set monitoring mode of all 3 to reporting
        set_monitoring_mode(session, subscription_id, triggered_item_ids[0], MonitoringMode::Reporting, &mis);
        set_monitoring_mode(session, subscription_id, triggered_item_ids[1], MonitoringMode::Reporting, &mis);
        set_monitoring_mode(session, subscription_id, triggered_item_ids[2], MonitoringMode::Reporting, &mis);

        // do a publish on the monitored item,
        let now = publish_tick_response(session, &ss, address_space, now, chrono::Duration::seconds(2), |response| {
            // TODO expect 0 other data changes
        });

        // revert to 3 items to be reporting, sampling, disabled
        set_monitoring_mode(session, subscription_id, triggered_item_ids[0], MonitoringMode::Reporting, &mis);
        set_monitoring_mode(session, subscription_id, triggered_item_ids[1], MonitoringMode::Sampling, &mis);
        set_monitoring_mode(session, subscription_id, triggered_item_ids[2], MonitoringMode::Disabled, &mis);

        // change monitoring mode of triggering item to sampling
        set_monitoring_mode(session, subscription_id, triggering_item_id, MonitoringMode::Sampling, &mis);

        // do a publish on the monitored item,
        let now = publish_tick_response(session, &ss, address_space, now, chrono::Duration::seconds(2), |response| {
            // TODO expect only 1 other data change corresponding to sampling  triggered item
        });

        // change monitoring mode of triggering item to disable
        set_monitoring_mode(session, subscription_id, triggering_item_id, MonitoringMode::Disabled, &mis);

        // do a publish on the monitored item, expect 0 data changes
        let now = publish_tick_response(session, &ss, address_space, now, chrono::Duration::seconds(2), |response| {
            // TODO expect 0 data changes
        });
    });
}

#[test]
fn monitored_item_queue_discard_oldest() {
    // The purpose of this test is to monitor the discard oldest behaviour. Depending on true/false
    // the oldest or newest item will be overwritten when the queue is full

    // discard_oldest = true
    {
        let mut monitored_item = populate_monitored_item(true);
        assert_first_notification_is_i32(&mut monitored_item, 1);
        assert_first_notification_is_i32(&mut monitored_item, 2);
        assert_first_notification_is_i32(&mut monitored_item, 3);
        assert_first_notification_is_i32(&mut monitored_item, 4);
        assert_first_notification_is_i32(&mut monitored_item, 10);
    }

    // discard_oldest = false
    {
        let mut monitored_item = populate_monitored_item(false);
        assert_first_notification_is_i32(&mut monitored_item, 0);
        assert_first_notification_is_i32(&mut monitored_item, 1);
        assert_first_notification_is_i32(&mut monitored_item, 2);
        assert_first_notification_is_i32(&mut monitored_item, 3);
        assert_first_notification_is_i32(&mut monitored_item, 10);
    }
}
