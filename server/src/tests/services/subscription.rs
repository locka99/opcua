use super::*;
use prelude::*;

#[test]
fn publish_response_subscription() {
    let st = ServiceTest::new();
    // Create a session
    // Create a subscription with a monitored item
    // Tick a change on the monitored item
    // Send a publish and expect a publish response containing the subscription
}

#[test]
fn multiple_publish_response_subscription() {
    let st = ServiceTest::new();
    // Create a session
    // create a subscription with a monitored item
    // Send a publish and expect nothing
    // Tick a change
    // Expect a publish response containing the subscription to be pushed
}
