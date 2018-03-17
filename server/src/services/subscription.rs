use std::result::Result;

use opcua_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::*;

use subscriptions::subscription::Subscription;
use state::ServerState;
use session::Session;
use services::Service;
use address_space::address_space::AddressSpace;

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
            self.service_fault(&request.request_header, BadTooManySubscriptions)
        } else {
            let subscription_id = server_state.create_subscription_id();

            // Check the requested publishing interval and keep alive values
            let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
                Self::revise_subscription_values(server_state, request.requested_publishing_interval, request.requested_max_keep_alive_count, request.requested_lifetime_count);

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
            return Ok(self.service_fault(&request.request_header, BadSubscriptionIdInvalid));
        } else {
            let subscription = subscriptions.get_mut(subscription_id).unwrap();

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
    pub fn delete_subscriptions(&self, session: &mut Session, request: DeleteSubscriptionsRequest) -> Result<SupportedMessage, StatusCode> {
        if request.subscription_ids.is_none() {
            Ok(self.service_fault(&request.request_header, BadNothingToDo))
        } else {
            let results = {
                let subscription_ids = request.subscription_ids.as_ref().unwrap();
                let mut results = Vec::with_capacity(subscription_ids.len());

                let subscriptions = &mut session.subscriptions;
                for subscription_id in subscription_ids {
                    let subscription = subscriptions.remove(*subscription_id);
                    if subscription.is_some() {
                        results.push(Good);
                    } else {
                        results.push(BadSubscriptionIdInvalid);
                    }
                }
                Some(results)
            };
            let diagnostic_infos = None;
            let response = DeleteSubscriptionsResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results,
                diagnostic_infos,
            };
            Ok(SupportedMessage::DeleteSubscriptionsResponse(response))
        }
    }

    /// Handles a SerPublishingModeRequest
    pub fn set_publishing_mode(&self, session: &mut Session, request: SetPublishingModeRequest) -> Result<SupportedMessage, StatusCode> {
        if request.subscription_ids.is_none() {
            Ok(self.service_fault(&request.request_header, BadNothingToDo))
        } else {
            let results = {
                let publishing_enabled = request.publishing_enabled;
                let subscription_ids = request.subscription_ids.as_ref().unwrap();
                let mut results = Vec::with_capacity(subscription_ids.len());
                let subscriptions = &mut session.subscriptions;
                for subscription_id in subscription_ids {
                    if let Some(subscription) = subscriptions.get_mut(*subscription_id) {
                        subscription.publishing_enabled = publishing_enabled;
                        results.push(Good);
                    } else {
                        results.push(BadSubscriptionIdInvalid);
                    }
                }
                Some(results)
            };
            let diagnostic_infos = None;
            let response = SetPublishingModeResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results,
                diagnostic_infos,
            };
            Ok(SupportedMessage::SetPublishingModeResponse(response))
        }
    }

    /// Handles a PublishRequest. This is asynchronous, so the response will be sent later on.
    pub fn publish(&self, session: &mut Session, request_id: UInt32, address_space: &AddressSpace, request: PublishRequest) -> Result<Option<SupportedMessage>, StatusCode> {
        trace!("--> Receive a PublishRequest {:?}", request);
        if session.subscriptions.is_empty() {
            Ok(Some(self.service_fault(&request.request_header, BadNoSubscription)))
        } else {
            let request_header = request.request_header.clone();
            let result = session.enqueue_publish_request(address_space, request_id, request);
            if let Err(error) = result {
                Ok(Some(self.service_fault(&request_header, error)))
            } else {
                Ok(None)
            }
        }
    }

    /// Handles a RepublishRequest
    pub fn republish(&self, session: &mut Session, request: RepublishRequest) -> Result<SupportedMessage, StatusCode> {
        trace!("Republish {:?}", request);
        // Look for a matching notification message
        let result = session.subscriptions.find_notification_message(request.subscription_id, request.retransmit_sequence_number);
        if let Ok(notification_message) = result {
            let response = RepublishResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                notification_message,
            };
            Ok(SupportedMessage::RepublishResponse(response))
        } else {
            Ok(self.service_fault(&request.request_header, result.unwrap_err()))
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
        let min_keep_alive_count = revised_max_keep_alive_count * 3;
        let revised_lifetime_count = if requested_lifetime_count < min_keep_alive_count {
            min_keep_alive_count
        } else {
            requested_lifetime_count
        };
        (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count)
    }
}