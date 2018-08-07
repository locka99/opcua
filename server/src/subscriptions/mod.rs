use opcua_types::{UInt32, SupportedMessage};
use opcua_types::service_types::PublishRequest;

/// The publish request entry preserves the request_id which is part of the chunk layer but clients
/// are fickle about receiving responses from the same as the request. Normally this is easy because
/// request and response are synchronous, but publish requests are async, so we preserve the request_id
/// so that later we can send out responses that have the proper req id
#[derive(Clone)]
pub struct PublishRequestEntry {
    pub request_id: UInt32,
    pub request: PublishRequest,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublishResponseEntry {
    pub request_id: UInt32,
    pub response: SupportedMessage,
}

use time;

/// This converts an OPC UA Duration into a time duration used for testing for interval elapsed
fn duration_from_ms(d: f64) -> time::Duration {
    // TODO duration is a floating point number of mills so really it should be scaled to micros
    // or nanos
    time::Duration::milliseconds(d as i64)
}

pub mod subscriptions;
pub mod subscription;
pub mod monitored_item;
