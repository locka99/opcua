use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use server::ServerState;
use tcp_transport::SessionState;

pub struct SubscriptionService {}

impl SubscriptionService {
    pub fn new() -> SubscriptionService {
        SubscriptionService {}
    }

    pub fn create_subscription(&self, _: &mut ServerState, _: &mut SessionState, request: &CreateSubscriptionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        debug!("create_subscription {:#?}", request);

        // TODO create a subscription
        /*
        pub request_header: RequestHeader,
        pub requested_publishing_interval: Double,
        pub requested_lifetime_count: UInt32,
        pub requested_max_keep_alive_count: UInt32,
        pub max_notifications_per_publish: UInt32,
        pub publishing_enabled: Boolean,
        pub priority: Byte, */

        let subscription_id = 1; // TODO
        let revised_publishing_interval = request.requested_publishing_interval;
        let revised_lifetime_count = request.requested_lifetime_count;
        let revised_max_keep_alive_count = request.requested_max_keep_alive_count;

        let response = CreateSubscriptionResponse {
            response_header: ResponseHeader::new(&DateTime::now(), request.request_header.request_handle),
            subscription_id: subscription_id,
            revised_publishing_interval: revised_publishing_interval,
            revised_lifetime_count: revised_lifetime_count,
            revised_max_keep_alive_count: revised_max_keep_alive_count,
        };
        Ok(SupportedMessage::CreateSubscriptionResponse(response))
    }

    pub fn publish(&self, _: &mut ServerState, _: &mut SessionState, request: &PublishRequest) -> Result<SupportedMessage, &'static StatusCode> {
        Err(&BAD_SERVICE_UNSUPPORTED)
    }
}