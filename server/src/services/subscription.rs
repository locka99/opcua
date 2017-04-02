use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use subscriptions::*;
use server::ServerState;
use session::SessionState;

pub struct SubscriptionService {}

impl SubscriptionService {
    pub fn new() -> SubscriptionService {
        SubscriptionService {}
    }

    /// Handles a CreateSubscriptionRequest
    pub fn create_subscription(&self, server_state: &mut ServerState, session_state: &mut SessionState, request: CreateSubscriptionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let mut subscriptions = session_state.subscriptions.lock().unwrap();
        let response = if server_state.max_subscriptions > 0 && subscriptions.len() >= server_state.max_subscriptions {
            CreateSubscriptionResponse {
                response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, &BAD_TOO_MANY_SUBSCRIPTIONS),
                subscription_id: 0,
                revised_publishing_interval: 0f64,
                revised_lifetime_count: 0,
                revised_max_keep_alive_count: 0,
            }
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
            CreateSubscriptionResponse {
                response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, &GOOD),
                subscription_id: subscription_id,
                revised_publishing_interval: revised_publishing_interval,
                revised_lifetime_count: revised_lifetime_count,
                revised_max_keep_alive_count: revised_max_keep_alive_count,
            }
        };
        Ok(SupportedMessage::CreateSubscriptionResponse(response))
    }

    /// Handles a ModifySubscriptionRequest
    pub fn modify_subscription(&self, server_state: &mut ServerState, session_state: &mut SessionState, request: ModifySubscriptionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let mut subscriptions = session_state.subscriptions.lock().unwrap();
        let subscription_id = request.subscription_id;
        let response = if !subscriptions.contains_key(&subscription_id) {
            ModifySubscriptionResponse {
                response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, &BAD_SUBSCRIPTION_ID_INVALID),
                revised_publishing_interval: 0f64,
                revised_lifetime_count: 0,
                revised_max_keep_alive_count: 0,
            }
        } else {
            let mut subscription = subscriptions.get_mut(&subscription_id).unwrap();

            let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
                SubscriptionService::revise_subscription_values(server_state, request.requested_publishing_interval, request.requested_max_keep_alive_count, request.requested_lifetime_count);

            subscription.publishing_interval = revised_publishing_interval;
            subscription.max_keep_alive_count = revised_max_keep_alive_count;
            subscription.max_lifetime_count = revised_lifetime_count;
            subscription.priority = request.priority;
            // ...max_notifications_per_publish??

            ModifySubscriptionResponse {
                response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, &GOOD),
                revised_publishing_interval: revised_publishing_interval,
                revised_lifetime_count: revised_lifetime_count,
                revised_max_keep_alive_count: revised_max_keep_alive_count,
            }
        };

        Ok(SupportedMessage::ModifySubscriptionResponse(response))
    }

    /// Handles a DeleteSubscriptionsRequest
    pub fn delete_subscriptions(&self, _: &mut ServerState, session_state: &mut SessionState, request: DeleteSubscriptionsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let (service_status, results) = if request.subscription_ids.is_some() {
            let subscription_ids = request.subscription_ids.as_ref().unwrap();
            let mut results = Vec::with_capacity(subscription_ids.len());

            let mut subscriptions = session_state.subscriptions.lock().unwrap();
            for subscription_id in subscription_ids {
                if subscriptions.contains_key(subscription_id) {
                    subscriptions.remove(subscription_id);
                    results.push(GOOD.clone());
                } else {
                    results.push(BAD_SUBSCRIPTION_ID_INVALID.clone());
                }
            }
            (&GOOD, Some(results))
        } else {
            (&BAD_NOTHING_TO_DO, None)
        };
        let response = DeleteSubscriptionsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::DeleteSubscriptionsResponse(response))
    }

    /// Handles a SerPublishingModeRequest
    pub fn set_publishing_mode(&self, _:&mut ServerState, session_state: &mut SessionState, request: SetPublishingModeRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let (service_status, results) = if request.subscription_ids.is_none() {
            (&BAD_NOTHING_TO_DO, None)
        }
        else {
            let publishing_enabled = request.publishing_enabled;
            let subscription_ids = request.subscription_ids.as_ref().unwrap();
            let mut results = Vec::with_capacity(subscription_ids.len());
            let mut subscriptions = session_state.subscriptions.lock().unwrap();
            for subscription_id in subscription_ids {
                if subscriptions.contains_key(subscription_id) {
                    let mut subscription = subscriptions.get_mut(subscription_id).unwrap();
                    subscription.publishing_enabled = publishing_enabled;
                    results.push(GOOD.clone());
                } else {
                    results.push(BAD_SUBSCRIPTION_ID_INVALID.clone());
                }
            }
            (&GOOD, Some(results))
        };
        let response = SetPublishingModeResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::SetPublishingModeResponse(response))
    }

    /// Handles a PublishRequest
    pub fn publish(&self, server_state: &mut ServerState, session_state: &mut SessionState, request_id: UInt32, request: PublishRequest) -> Result<SupportedMessage, &'static StatusCode> {
        error!("RECEIVED A PUBLISHREQUEST {:#?}", request);
        let message = session_state.enqueue_publish_request(server_state, request_id, request)?;
        if message.is_some() {
            error!("GOT SOME MESSAGES TO SEND OUT");
            Ok(SupportedMessage::MultipleMessages(Box::new(message.unwrap())))
        }
        else {
            Ok(SupportedMessage::DoNothing)
        }
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