use std::result::Result;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use types::*;
use server::ServerState;

pub struct SubscriptionService {}

// TODO this should be a server configurable setting. Its set low to make it more likely to trigger
const MAX_SUBSCRIPTIONS: usize = 2;

impl SubscriptionService {
    pub fn new() -> SubscriptionService {
        SubscriptionService {}
    }

    pub fn poll(&self, session_state: &mut SessionState) {
        let publishing_enabled = true;
        let more_notifications = false;

        for (subscription_id, subscription) in session_state.subscriptions.iter() {
            match subscription.state {
                SubscriptionState::Closed => {
                    // DO NOTHING
                },
                SubscriptionState::Creating => {},
                SubscriptionState::Normal => {},
                SubscriptionState::KeepAlive => {},
                SubscriptionState::Late => {},
            }
        }
    }

    pub fn create_subscription(&self, _: &mut ServerState, session_state: &mut SessionState, request: &CreateSubscriptionRequest) -> Result<SupportedMessage, &'static StatusCode> {
        if session_state.subscriptions.len() >= MAX_SUBSCRIPTIONS {
            return Err(&BAD_TOO_MANY_SUBSCRIPTIONS);
        }

        let service_status = &GOOD;

        let subscription_id = session_state.last_subscription_id + 1;
        // TODO server settings could revise these in some way
        let revised_publishing_interval = request.requested_publishing_interval;
        let revised_lifetime_count = request.requested_lifetime_count;
        let revised_max_keep_alive_count = request.requested_max_keep_alive_count;

        // Create a new subscription
        let subscription = Subscription {
            subscription_id: subscription_id,
            state: SubscriptionState::Creating,
            publishing_interval: revised_publishing_interval,
            lifetime_count: revised_lifetime_count,
            keep_alive_count: revised_max_keep_alive_count,
            priority: request.priority,
            monitored_items: Vec::new(),
        };
        session_state.last_subscription_id += 1;
        session_state.subscriptions.insert(subscription_id, subscription);

        // Create the response
        let response = CreateSubscriptionResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            subscription_id: subscription_id,
            revised_publishing_interval: revised_publishing_interval,
            revised_lifetime_count: revised_lifetime_count,
            revised_max_keep_alive_count: revised_max_keep_alive_count,
        };
        Ok(SupportedMessage::CreateSubscriptionResponse(response))
    }

    pub fn delete_subscriptions(&self, _: &mut ServerState, session_state: &mut SessionState, request: &DeleteSubscriptionsRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let mut service_status = &GOOD;
        let results = if request.subscription_ids.is_some() {
            let subscription_ids = request.subscription_ids.as_ref().unwrap();
            let mut results = Vec::with_capacity(subscription_ids.len());
            for subscription_id in subscription_ids {
                if session_state.subscriptions.contains_key(subscription_id) {
                    session_state.subscriptions.remove(subscription_id);
                    results.push(GOOD.clone());
                } else {
                    results.push(BAD_SUBSCRIPTION_ID_INVALID.clone());
                }
            }
            Some(results)
        } else {
            service_status = &BAD_NOTHING_TO_DO;
            None
        };

        let response = DeleteSubscriptionsResponse {
            response_header: ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status),
            results: results,
            diagnostic_infos: None
        };
        Ok(SupportedMessage::DeleteSubscriptionsResponse(response))
    }

    pub fn publish(&self, _: &mut ServerState, _: &mut SessionState, request: &PublishRequest) -> Result<SupportedMessage, &'static StatusCode> {
        let service_status = &GOOD;

        if request.subscription_acknowledgements.is_some() {
            // TODO
            // The list of acknowledgements for one or more Subscriptions. This list may contain
            // multiple acknowledgements for the same Subscription (multiple entries with the same
            // subscriptionId). This structure is defined in-line with the following indented items.
        }

        let now = DateTime::now();

        let notification_message = NotificationMessage {
            sequence_number: 0,
            publish_time: now.clone(),
            notification_data: None
        };

        let response = PublishResponse {
            response_header: ResponseHeader::new_service_result(&now, &request.request_header, service_status),
            subscription_id: 0,
            available_sequence_numbers: None,
            more_notifications: false,
            notification_message: notification_message,
            results: None,
            diagnostic_infos: None
        };

        Ok(SupportedMessage::PublishResponse(response))
    }
}