use chrono;

use prelude::*;

fn make_subscription() -> Subscription {
    let subscription_interval = 1000f64;
    Subscription::new(0, true, subscription_interval, 9, 3, 0)
}

#[test]
fn basic_subscription() {
    let s = make_subscription();
    assert!(s.state == SubscriptionState::Creating);
}

#[test]
fn update_state_3() {
    let mut s = make_subscription();
    let mut publish_requests: Vec<PublishRequest> = vec!();

    // Test #3 - state changes from Creating -> Normal
    let now = chrono::UTC::now();
    let items_changed = false;
    let publishing_timer_expired = false;
    s.update_state(&mut publish_requests, &now, items_changed, publishing_timer_expired);

    assert_eq!(s.message_sent, false);
    assert_eq!(s.state, SubscriptionState::Normal);
}

#[test]
fn update_state_4() {
    let mut s = make_subscription();
    let mut publish_requests: Vec<PublishRequest> = vec!(
        PublishRequest {
            request_header: RequestHeader::new(&NodeId::null(), &DateTime::now(), 1),
            subscription_acknowledgements: None,
        }
    );

    // Test #4 -

    // Receive Publish Request
    //    &&
    //    (
    //        PublishingEnabled == FALSE
    //            ||
    //            (PublishingEnabled == TRUE
    //                && MoreNotifications == FALSE)
    //    )

    let now = chrono::UTC::now();
    let items_changed = false;
    let publishing_timer_expired = false;

    s.state = SubscriptionState::Normal;
    s.publishing_enabled = false;

    s.update_state(&mut publish_requests, &now, items_changed, publishing_timer_expired);

    //DeleteAckedNotificationMsgs()
    //EnqueuePublishingReq()


    assert_eq!(s.state, SubscriptionState::Normal);
}

