use prelude::*;
use subscriptions::subscription::SubscriptionStateParams;

const DEFAULT_LIFETIME_COUNT: UInt32 = 300;
const DEFAULT_KEEPALIVE_COUNT: UInt32 = 100;

fn make_subscription(state: SubscriptionState) -> Subscription {
    let subscription_interval = 1000f64;
    let mut result = Subscription::new(0, true, subscription_interval, DEFAULT_LIFETIME_COUNT, DEFAULT_KEEPALIVE_COUNT, 0);
    result.state = state;
    result
}

#[test]
fn basic_subscription() {
    let s = Subscription::new(0, true, 1000f64, DEFAULT_LIFETIME_COUNT, DEFAULT_KEEPALIVE_COUNT, 0);
    assert_eq!(s.state, SubscriptionState::Creating);
}

// The update_state_ tests below test with a set of inputs and expect a set of outputs that
// indicate the subscription has moved from one state to another.

#[test]
fn update_state_3() {
    let mut s = make_subscription(SubscriptionState::Creating);

    // Test #3 - state changes from Creating -> Normal
    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: false,
    };

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 3);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.message_sent, false);
}

#[test]
fn update_state_4() {
    // Test #4 -
    // Create a subscription in the normal state, and an incoming publish request. Tick on a subscription
    // with no changes and ensure the request is still queued afterwards

    let mut s = make_subscription(SubscriptionState::Normal);

    // Receive Publish Request
    //    &&
    //    (
    //        PublishingEnabled == FALSE
    //            ||
    //            (PublishingEnabled == TRUE
    //                && MoreNotifications == FALSE)
    //    )
    let tick_reason = TickReason::ReceivedPublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: false,
    };

    s.publishing_enabled = false;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 4);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(s.state, SubscriptionState::Normal);

    // TODO repeat with publishing enabled true, more notifications false
}

#[test]
fn update_state_5() {
    // Test #5
    // Queue a publish request, publishing on, more notifications.
    // Ensure return notifications action

    let mut s = make_subscription(SubscriptionState::Normal);

    // TODO publish request should include some acknowledgements

    // queue publish request
    // set publish enabled true
    // set more notifications true

    let tick_reason = TickReason::ReceivedPublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: true,
        publishing_req_queued: true,
        publishing_interval_elapsed: false,
    };

    s.publishing_enabled = true;
    s.lifetime_counter = 1;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 5);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
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

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: true,
    };

    s.publishing_enabled = true;
    s.lifetime_counter = 3; // Expect this to be reset

    let update_state_result = s.update_state(tick_reason, p);

    // ensure 6
    assert_eq!(update_state_result.handled_state, 6);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.lifetime_counter, 299);
    assert_eq!(s.message_sent, true);
}

#[test]
fn update_state_7() {
    // set timer expires
    // publishing request queued true
    // message sent true
    // publishing enabled false

    let mut s = make_subscription(SubscriptionState::Normal);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: true,
    };

    s.message_sent = false;
    s.publishing_enabled = false;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 7);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnKeepAlive);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.lifetime_counter, 299);
    assert_eq!(s.message_sent, true);

    // TODO Repeat with publishing enabled true and notifications available false
}

#[test]
fn update_state_8() {
    // set timer expires
    // set publishing request queued false
    // set message_sent false

    let mut s = make_subscription(SubscriptionState::Normal);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: false,
        publishing_interval_elapsed: true,
    };
    s.message_sent = false;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 8);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(s.state, SubscriptionState::Late);
    // ensure start publishing timer
}

#[test]
fn update_state_9() {
    // set timer expires
    // set publishing request queued false
    // set message_sent false

    let mut s = make_subscription(SubscriptionState::Normal);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: false,
        publishing_interval_elapsed: true,
    };

    s.message_sent = true;
    s.publishing_enabled = false;
    s.keep_alive_counter = 3;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 9);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter, s.max_keep_alive_count);
}

#[test]
fn update_state_10() {
    let mut s = make_subscription(SubscriptionState::Late);

    let tick_reason = TickReason::ReceivedPublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: false,
    };

    s.publishing_enabled = true;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 10);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
    assert_eq!(s.state, SubscriptionState::Normal);
    assert_eq!(s.message_sent, true);
}

#[test]
fn update_state_11() {
    let mut s = make_subscription(SubscriptionState::Late);

    let tick_reason = TickReason::ReceivedPublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: false,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: false,
    };

    s.publishing_enabled = true;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 11);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnKeepAlive);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
    assert_eq!(s.message_sent, true);
}

#[test]
fn update_state_12() {
    let mut s = make_subscription(SubscriptionState::Late);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: false,
        more_notifications: false,
        publishing_req_queued: false,
        publishing_interval_elapsed: true,
    };

    s.publishing_enabled = true;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 12);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(s.state, SubscriptionState::Late);
}

#[test]
fn update_state_13() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let tick_reason = TickReason::ReceivedPublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: false,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: false,
    };

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 13);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
}

#[test]
fn update_state_14() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: true,
    };

    s.publishing_enabled = true;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 14);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnNotifications);
    assert_eq!(s.state, SubscriptionState::Normal);
}

#[test]
fn update_state_15() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: true,
    };

    s.keep_alive_counter = 1;
    s.publishing_enabled = false;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 15);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::ReturnKeepAlive);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter, s.max_keep_alive_count);
}

#[test]
fn update_state_16() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    s.keep_alive_counter = 5;
    s.publishing_enabled = false;

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_interval_elapsed: true,
    };

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 16);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(s.state, SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter, 4);
}

#[test]
fn update_state_17() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: false,
        publishing_interval_elapsed: true,
    };

    s.keep_alive_counter = 1;

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, 17);
    assert_eq!(update_state_result.update_state_action, UpdateStateAction::None);
    assert_eq!(s.state, SubscriptionState::Late);
    assert_eq!(s.keep_alive_counter, 1);
}
