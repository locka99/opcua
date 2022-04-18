use std::sync::Arc;

use crate::server::{
    diagnostics::ServerDiagnostics,
    subscriptions::subscription::{
        HandledState, Subscription, SubscriptionState, SubscriptionStateParams, TickReason,
        UpdateStateAction,
    },
};
use crate::sync::*;

const DEFAULT_LIFETIME_COUNT: u32 = 300;
const DEFAULT_KEEPALIVE_COUNT: u32 = 100;

fn make_subscription(state: SubscriptionState) -> Subscription {
    let subscription_interval = 1000f64;
    let mut result = Subscription::new(
        Arc::new(RwLock::new(ServerDiagnostics::default())),
        0,
        true,
        subscription_interval,
        DEFAULT_LIFETIME_COUNT,
        DEFAULT_KEEPALIVE_COUNT,
        0,
    );
    result.set_state(state);
    result
}

#[test]
fn basic_subscription() {
    let s = Subscription::new(
        Arc::new(RwLock::new(ServerDiagnostics::default())),
        0,
        true,
        1000f64,
        DEFAULT_LIFETIME_COUNT,
        DEFAULT_KEEPALIVE_COUNT,
        0,
    );
    assert_eq!(s.state(), SubscriptionState::Creating);
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
        publishing_timer_expired: false,
    };

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::Create3);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::SubscriptionCreated
    );
    assert_eq!(s.state(), SubscriptionState::Normal);
    assert_eq!(s.message_sent(), false);
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
    let tick_reason = TickReason::ReceivePublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_timer_expired: false,
    };

    s.set_publishing_enabled(false);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::Normal4);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::None
    );
    assert_eq!(s.state(), SubscriptionState::Normal);

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

    let tick_reason = TickReason::ReceivePublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: true,
        publishing_req_queued: true,
        publishing_timer_expired: false,
    };

    s.set_publishing_enabled(true);
    s.set_current_lifetime_count(10);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::Normal5);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::ReturnNotifications
    );
    assert_eq!(s.state(), SubscriptionState::Normal);
    assert_eq!(s.lifetime_counter(), s.max_lifetime_count());
    assert_eq!(s.message_sent(), true);

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
        publishing_timer_expired: true,
    };

    s.set_publishing_enabled(true);
    s.set_current_lifetime_count(3); // Expect this to be reset

    let update_state_result = s.update_state(tick_reason, p);

    // ensure 6
    assert_eq!(
        update_state_result.handled_state,
        HandledState::IntervalElapsed6
    );
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::ReturnNotifications
    );
    assert_eq!(s.state(), SubscriptionState::Normal);
    assert_eq!(s.lifetime_counter(), 299);
    assert_eq!(s.message_sent(), true);
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
        publishing_timer_expired: true,
    };

    s.set_message_sent(false);
    s.set_publishing_enabled(false);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(
        update_state_result.handled_state,
        HandledState::IntervalElapsed7
    );
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::ReturnKeepAlive
    );
    assert_eq!(s.state(), SubscriptionState::Normal);
    assert_eq!(s.lifetime_counter(), 299);
    assert_eq!(s.message_sent(), true);

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
        publishing_timer_expired: true,
    };
    s.set_message_sent(false);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(
        update_state_result.handled_state,
        HandledState::IntervalElapsed8
    );
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::None
    );
    assert_eq!(s.state(), SubscriptionState::Late);
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
        publishing_timer_expired: true,
    };

    s.set_message_sent(true);
    s.set_publishing_enabled(false);
    s.set_keep_alive_counter(3);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(
        update_state_result.handled_state,
        HandledState::IntervalElapsed9
    );
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::None
    );
    assert_eq!(s.state(), SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter(), s.max_keep_alive_count());
}

#[test]
fn update_state_10() {
    let mut s = make_subscription(SubscriptionState::Late);

    let tick_reason = TickReason::ReceivePublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_timer_expired: false,
    };

    s.set_publishing_enabled(true);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::Late10);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::ReturnNotifications
    );
    assert_eq!(s.state(), SubscriptionState::Normal);
    assert_eq!(s.message_sent(), true);
}

#[test]
fn update_state_11() {
    let mut s = make_subscription(SubscriptionState::Late);

    let tick_reason = TickReason::ReceivePublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: false,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_timer_expired: false,
    };

    s.set_publishing_enabled(true);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::Late11);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::ReturnKeepAlive
    );
    assert_eq!(s.state(), SubscriptionState::KeepAlive);
    assert_eq!(s.message_sent(), true);
}

#[test]
fn update_state_12() {
    let mut s = make_subscription(SubscriptionState::Late);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: false,
        more_notifications: false,
        publishing_req_queued: false,
        publishing_timer_expired: true,
    };

    s.set_publishing_enabled(true);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::Late12);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::None
    );
    assert_eq!(s.state(), SubscriptionState::Late);
}

#[test]
fn update_state_13() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let tick_reason = TickReason::ReceivePublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: false,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_timer_expired: false,
    };

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::KeepAlive13);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::None
    );
    assert_eq!(s.state(), SubscriptionState::KeepAlive);
}

#[test]
fn update_state_14() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_timer_expired: true,
    };

    s.set_publishing_enabled(true);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::KeepAlive14);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::ReturnNotifications
    );
    assert_eq!(s.state(), SubscriptionState::Normal);
}

#[test]
fn update_state_15() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_timer_expired: true,
    };

    s.set_keep_alive_counter(1);
    s.set_publishing_enabled(false);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::KeepAlive15);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::ReturnKeepAlive
    );
    assert_eq!(s.state(), SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter(), s.max_keep_alive_count());
}

#[test]
fn update_state_16() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    s.set_keep_alive_counter(5);
    s.set_publishing_enabled(false);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: true,
        publishing_timer_expired: true,
    };

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::KeepAlive16);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::None
    );
    assert_eq!(s.state(), SubscriptionState::KeepAlive);
    assert_eq!(s.keep_alive_counter(), 4);
}

#[test]
fn update_state_17() {
    let mut s = make_subscription(SubscriptionState::KeepAlive);

    let tick_reason = TickReason::TickTimerFired;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: false,
        publishing_req_queued: false,
        publishing_timer_expired: true,
    };

    s.set_keep_alive_counter(1);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::KeepAlive17);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::None
    );
    assert_eq!(s.state(), SubscriptionState::Late);
    assert_eq!(s.keep_alive_counter(), 1);
}

#[test]
fn update_state_27() {
    // Test #27
    // Queue a publish request, publishing on, more notifications, lifetime of 1

    // Ensure subscription is closed, update action to close expired subscription

    let mut s = make_subscription(SubscriptionState::Normal);

    // queue publish request
    // set publish enabled true
    // set more notifications true

    let tick_reason = TickReason::ReceivePublishRequest;
    let p = SubscriptionStateParams {
        notifications_available: true,
        more_notifications: true,
        publishing_req_queued: true,
        publishing_timer_expired: false,
    };

    s.set_publishing_enabled(true);
    s.set_current_lifetime_count(1);

    let update_state_result = s.update_state(tick_reason, p);

    assert_eq!(update_state_result.handled_state, HandledState::Closed27);
    assert_eq!(
        update_state_result.update_state_action,
        UpdateStateAction::SubscriptionExpired
    );
    assert_eq!(s.state(), SubscriptionState::Closed);
    assert_eq!(s.lifetime_counter(), 1);
    assert_eq!(s.message_sent(), false);
}
