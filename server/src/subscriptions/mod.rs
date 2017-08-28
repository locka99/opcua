use opcua_types::{UInt32, PublishRequest, SupportedMessage};


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

pub mod subscriptions;
pub mod subscription;
pub mod monitored_item;
