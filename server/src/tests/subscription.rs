use prelude::*;

const DEFAULT_LIFETIME_COUNT: UInt32 = 300;
const DEFAULT_KEEPALIVE_COUNT: UInt32 = 100;

fn make_subscription(state: SubscriptionState) -> Subscription {
    let subscription_interval = 1000f64;
    let mut result = Subscription::new(0, true, subscription_interval, DEFAULT_LIFETIME_COUNT, DEFAULT_KEEPALIVE_COUNT, 0);
    result.state = state;
    result
}

fn make_publish_request() -> PublishRequest {
    PublishRequest {
        request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
        subscription_acknowledgements: None,
    }
}

#[test]
fn basic_subscription() {
    let s = Subscription::new(0, true, 1000f64, DEFAULT_LIFETIME_COUNT, DEFAULT_KEEPALIVE_COUNT, 0);
    assert!(s.state == SubscriptionState::Creating);
}

#[test]
fn update_state_3() {
    let mut s = make_subscription(SubscriptionState::Creating);
    let publish_request = None;

    // Test #3 - state changes from Creating -> Normal
    let publishing_timer_expired = false;
    let receive_publish_request = false;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 3);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.message_sent, false);
}

#[test]
fn update_state_4() {
    // Test #4 -
    // Create a subscription in the normal state, and an incoming publish request. Tick on a subscription
    // with no changes and ensure the request is still queued afterwards

    let mut s = make_subscription(SubscriptionState::Normal);

    let publish_request = Some(make_publish_request());
    let receive_publish_request = true;
    let publishing_timer_expired = false;

    // Receive Publish Request
    //    &&
    //    (
    //        PublishingEnabled == FALSE
    //            ||
    //            (PublishingEnabled == TRUE
    //                && MoreNotifications == FALSE)
    //    )

    s.publishing_enabled = false;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 4);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::Normal);

    // TODO repeat with publishing enabled true, more notifications false
}

#[test]
fn update_state_5() {
    // Test #5
    // Queue a publish request, publishing on, more notifications.
    // Ensure return notifications action

    let mut s = make_subscription(SubscriptionState::Normal);

    let publish_request = Some(make_publish_request());
    let receive_publish_request = true;
    let publishing_timer_expired = false;
    // TODO publish request should include some acknowledgements

    // queue publish request
    // set publish enabled true
    // set more notifications true

    s.publishing_enabled = true;
    s.more_notifications = true;
    s.lifetime_counter = 1;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 5);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.lifetime_counter, s.max_lifetime_count);
    assert_eq!(s.message_sent, true);

    // TODO ensure deleted acknowledged notification msgs
}

#[test]
fn update_state_6() {
    // set publishing timer expires
    // set publishing requ queued
    // set publishing enabled true
    // set notifications available true

    let mut s = make_subscription(SubscriptionState::Normal);

    let publish_request = None;
    let receive_publish_request = false;
    let publishing_timer_expired = true;

    s.publishing_enabled = true;
    s.notifications_available = true;
    s.lifetime_counter = 3; // Expect this to be reset
    s.publishing_req_queued = true;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    // ensure 6
    assert_eq!(update_state_result.handled_state, 6);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::Dequeue);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.lifetime_counter, s.max_lifetime_count);
    assert_eq!(s.message_sent, true);
}

#[test]
fn update_state_7() {
    // set timer expires
    // publishing request queued true
    // message sent true
    // publishing enabled false

    let mut s = make_subscription(SubscriptionState::Normal);

    let publish_request = None;
    let receive_publish_request = false;
    let publishing_timer_expired = true;

    s.publishing_req_queued = true;
    s.message_sent = false;
    s.publishing_enabled = true;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 7);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnKeepAlive);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::Dequeue);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.lifetime_counter, s.max_lifetime_count);
    assert_eq!(s.message_sent, true);

    // TODO Repeat with publishing enabled true and notifications available false
}

#[test]
fn update_state_8() {
    // set timer expires
    // set publishing request queued false
    // set message_sent false

    let mut s = make_subscription(SubscriptionState::Normal);

    let publish_request = None;
    let receive_publish_request = false;
    let publishing_timer_expired = true;

    s.publishing_req_queued = false;
    s.message_sent = false;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 8);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::Late);
    // ensure start publishing timer
}

#[test]
fn update_state_9() {
    // set timer expires
    // set publishing request queued false
    // set message_sent false

    let mut s = make_subscription(SubscriptionState::Normal);

    let publish_request = None;
    let receive_publish_request = false;
    let publishing_timer_expired = true;

    s.message_sent = true;
    s.publishing_enabled = false;
    s.keep_alive_counter = 3;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 9);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter, s.max_keep_alive_count);
}

#[test]
fn update_state_10() {
    let mut s = make_subscription(SubscriptionState::Late);

    let publish_request = Some(make_publish_request());
    let receive_publish_request = true;
    let publishing_timer_expired = false;

    s.publishing_enabled = true;
    s.notifications_available = true;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 10);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.message_sent, true);
}

#[test]
fn update_state_11() {
    let mut s = make_subscription(SubscriptionState::Late);

    let publish_request = Some(make_publish_request());
    let receive_publish_request = true;
    let publishing_timer_expired = false;

    s.publishing_enabled = true;
    s.notifications_available = false;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 11);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnKeepAlive);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
    assert_eq!(s.message_sent, true);
}

#[test]
fn update_state_12() {
    let mut s = make_subscription(SubscriptionState::Late);

    let publish_request = None;
    let receive_publish_request = false;
    let publishing_timer_expired = true;

    s.publishing_enabled = true;
    s.notifications_available = false;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 12);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::Late);
}

#[test]
fn update_state_13() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let publish_request = Some(make_publish_request());
    let receive_publish_request = true;
    let publishing_timer_expired = false;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 13);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
}

#[test]
fn update_state_14() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let publish_request = None;
    let publishing_timer_expired = true;
    let receive_publish_request = false;

    s.publishing_enabled = true;
    s.notifications_available = true;
    s.publishing_req_queued = true;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 14);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::Dequeue);
    assert_eq!(s.state, SubscriptionState::Normal);
}

#[test]
fn update_state_15() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let publish_request = None;

    let publishing_timer_expired = true;
    let receive_publish_request = false;

    s.publishing_req_queued = true;
    s.keep_alive_counter = 1;
    s.publishing_enabled = false;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 15);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnKeepAlive);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::Dequeue);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter, s.max_keep_alive_count);
}

#[test]
fn update_state_16() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let publish_request = None;

    let publishing_timer_expired = true;
    s.keep_alive_counter = 5;
    s.publishing_enabled = false;

    let receive_publish_request = false;
    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 16);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter, 4);
}

#[test]
fn update_state_17() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let publish_request = None;

    let publishing_timer_expired = true;
    let receive_publish_request = false;

    s.publishing_req_queued = false;
    s.keep_alive_counter = 1;

    let update_state_result = s.update_state(receive_publish_request, &publish_request, publishing_timer_expired);

    assert_eq!(update_state_result.handled_state, 17);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(update_state_result.publish_request_action, PublishRequestAction::None);
    assert_eq!(s.state, SubscriptionState::Late);
    assert_eq!(s.keep_alive_counter, 1);
}
