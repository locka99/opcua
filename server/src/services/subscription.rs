use std::result::Result;

use opcua_types::*;

use subscriptions::subscription::*;
use server::ServerState;
use session::Session;
use services::Service;

pub struct SubscriptionService {}

impl Service for SubscriptionService {}

impl SubscriptionService {
    pub fn new() -> SubscriptionService {
        SubscriptionService {}
    }

    /// Handles a CreateSubscriptionRequest
    pub fn create_subscription(&self, server_state: &mut ServerState, session: &mut Session, request: CreateSubscriptionRequest) -> Result<SupportedMessage, StatusCode> {
        let subscriptions = &mut session.subscriptions;
        let response = if server_state.max_subscriptions > 0 && subscriptions.len() >= server_state.max_subscriptions {
            self.service_fault(&request.request_header, BAD_TOO_MANY_SUBSCRIPTIONS)
        } else {
            let subscription_id = server_state.create_subscription_id();

            // Check the requested publishing interval and keep alive values
            let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
                SubscriptionService::revise_subscription_values(server_state, request.requested_publishing_interval, request.requested_max_keep_alive_count, request.requested_lifetime_count);

            // Create a new subscription
            let publishing_enabled = request.publishing_enabled;
            let subscription = Subscription::new(subscription_id, publishing_enabled, revised_publishing_interval, revised_lifetime_count, revised_max_keep_alive_count, request.priority);
            subscriptions.insert(subscription_id, subscription);

            // Create the response
            SupportedMessage::CreateSubscriptionResponse(CreateSubscriptionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                subscription_id,
                revised_publishing_interval,
                revised_lifetime_count,
                revised_max_keep_alive_count,
            })
        };
        Ok(response)
    }

    /// Handles a ModifySubscriptionRequest
    pub fn modify_subscription(&self, server_state: &mut ServerState, session: &mut Session, request: ModifySubscriptionRequest) -> Result<SupportedMessage, StatusCode> {
        let subscriptions = &mut session.subscriptions;
        let subscription_id = request.subscription_id;

        let response = if !subscriptions.contains(subscription_id) {
            return Ok(self.service_fault(&request.request_header, BAD_SUBSCRIPTION_ID_INVALID));
        } else {
            let mut subscription = subscriptions.get_mut(subscription_id).unwrap();

            let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
                SubscriptionService::revise_subscription_values(server_state, request.requested_publishing_interval, request.requested_max_keep_alive_count, request.requested_lifetime_count);

            subscription.publishing_interval = revised_publishing_interval;
            subscription.max_keep_alive_count = revised_max_keep_alive_count;
            subscription.max_lifetime_count = revised_lifetime_count;
            subscription.priority = request.priority;
            // ...max_notifications_per_publish??

            ModifySubscriptionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                revised_publishing_interval,
                revised_lifetime_count,
                revised_max_keep_alive_count,
            }
        };

        Ok(SupportedMessage::ModifySubscriptionResponse(response))
    }

    /// Handles a DeleteSubscriptionsRequest
    pub fn delete_subscriptions(&self, _: &mut ServerState, session: &mut Session, request: DeleteSubscriptionsRequest) -> Result<SupportedMessage, StatusCode> {
        if request.subscription_ids.is_none() {
            return Ok(self.service_fault(&request.request_header, BAD_NOTHING_TO_DO));
        }
        let results = {
            let subscription_ids = request.subscription_ids.as_ref().unwrap();
            let mut results = Vec::with_capacity(subscription_ids.len());

            let subscriptions = &mut session.subscriptions;
            for subscription_id in subscription_ids {
                let subscription = subscriptions.remove(*subscription_id);
                if subscription.is_some() {
                    results.push(GOOD);
                } else {
                    results.push(BAD_SUBSCRIPTION_ID_INVALID);
                }
            }
            Some(results)
        };
        let diagnostic_infos = None;
        let response = DeleteSubscriptionsResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results: results,
            diagnostic_infos,
        };
        Ok(SupportedMessage::DeleteSubscriptionsResponse(response))
    }

    /// Handles a SerPublishingModeRequest
    pub fn set_publishing_mode(&self, _: &mut ServerState, session: &mut Session, request: SetPublishingModeRequest) -> Result<SupportedMessage, StatusCode> {
        if request.subscription_ids.is_none() {
            return Ok(self.service_fault(&request.request_header, BAD_NOTHING_TO_DO));
        }
        let results = {
            let publishing_enabled = request.publishing_enabled;
            let subscription_ids = request.subscription_ids.as_ref().unwrap();
            let mut results = Vec::with_capacity(subscription_ids.len());
            let subscriptions = &mut session.subscriptions;
            for subscription_id in subscription_ids {
                if let Some(subscription) = subscriptions.get_mut(*subscription_id) {
                    subscription.publishing_enabled = publishing_enabled;
                    results.push(GOOD);
                } else {
                    results.push(BAD_SUBSCRIPTION_ID_INVALID);
                }
            }
            Some(results)
        };
        let diagnostic_infos = None;
        let response = SetPublishingModeResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results: results,
            diagnostic_infos,
        };
        Ok(SupportedMessage::SetPublishingModeResponse(response))
    }

    /// Handles a PublishRequest
    pub fn publish(&self, server_state: &mut ServerState, session: &mut Session, request_id: UInt32, request: PublishRequest) -> Result<SupportedMessage, StatusCode> {
        trace!("--> Receive a PublishRequest {:?}", request);
        let publish_responses = session.enqueue_publish_request(server_state, request_id, request)?;
        if publish_responses.is_some() {
            let mut publish_responses = publish_responses.unwrap();
            if publish_responses.len() != 1 {
                // A request should either get queued, consumed, or rejected resulting in one response at most
                panic!("Shouldn't receive more than one response to a publish request");
            }
            // We assume the publish response request_id is the same as the request here
            Ok(publish_responses.remove(0).response)
        } else {
            Ok(SupportedMessage::DoNothing)
        }
    }

    /// Handles a RepublishRequest
    pub fn republish(&self, _: &mut ServerState, _: &mut Session, request: RepublishRequest) -> Result<SupportedMessage, StatusCode> {
        // TODO look for the subscription id and sequence number in the sent items and resend it
        Ok(self.service_fault(&request.request_header, BAD_MESSAGE_NOT_AVAILABLE))
    }

    /// This function takes the requested values passed in a create / modify and returns revised
    /// values that conform to the server's limits. For simplicity the return type is a tuple
    fn revise_subscription_values(server_state: &ServerState, requested_publishing_interval: Duration, requested_max_keep_alive_count: UInt32, requested_lifetime_count: UInt32) -> (Duration, UInt32, UInt32) {
        let revised_publishing_interval = if requested_publishing_interval < server_state.min_publishing_interval {
            server_state.min_publishing_interval
        } else {
            requested_publishing_interval
        };
        let revised_max_keep_alive_count = if requested_max_keep_alive_count > server_state.max_keep_alive_count {
            server_state.max_keep_alive_count
        } else {
            requested_max_keep_alive_count
        };
        let max_keep_alive_count = revised_max_keep_alive_count * 3;
        let revised_lifetime_count = if requested_lifetime_count > max_keep_alive_count {
            max_keep_alive_count
        } else {
            requested_lifetime_count
        };
        (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count)
    }
}