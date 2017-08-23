use opcua_types::{UInt32, PublishRequest, SupportedMessage};

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
