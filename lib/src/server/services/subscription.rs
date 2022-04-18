// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::sync::Arc;

use crate::core::supported_message::SupportedMessage;
use crate::sync::*;
use crate::types::{status_code::StatusCode, *};

use crate::server::{
    address_space::AddressSpace, services::Service, session::Session, state::ServerState,
    subscriptions::subscription::Subscription,
};

/// The subscription service. Allows the client to create, modify and delete subscriptions of monitored items
/// on the server and to request publish of notifications.
pub(crate) struct SubscriptionService;

impl Service for SubscriptionService {
    fn name(&self) -> String {
        String::from("SubscriptionService")
    }
}

impl SubscriptionService {
    pub fn new() -> SubscriptionService {
        SubscriptionService {}
    }

    /// Handles a CreateSubscriptionRequest
    pub fn create_subscription(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        session: Arc<RwLock<Session>>,
        request: &CreateSubscriptionRequest,
    ) -> SupportedMessage {
        let mut server_state = trace_write_lock!(server_state);
        let mut session = trace_write_lock!(session);

        let subscriptions = session.subscriptions_mut();

        if server_state.max_subscriptions > 0
            && subscriptions.len() >= server_state.max_subscriptions
        {
            self.service_fault(&request.request_header, StatusCode::BadTooManySubscriptions)
        } else {
            let subscription_id = server_state.create_subscription_id();

            // Check the requested publishing interval and keep alive values
            let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
                Self::revise_subscription_values(
                    &server_state,
                    request.requested_publishing_interval,
                    request.requested_max_keep_alive_count,
                    request.requested_lifetime_count,
                );

            // Create a new subscription
            let publishing_enabled = request.publishing_enabled;
            let subscription = Subscription::new(
                server_state.diagnostics.clone(),
                subscription_id,
                publishing_enabled,
                revised_publishing_interval,
                revised_lifetime_count,
                revised_max_keep_alive_count,
                request.priority,
            );
            subscriptions.insert(subscription_id, subscription);

            // Create the response
            CreateSubscriptionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                subscription_id,
                revised_publishing_interval,
                revised_lifetime_count,
                revised_max_keep_alive_count,
            }
            .into()
        }
    }

    /// Handles a ModifySubscriptionRequest
    pub fn modify_subscription(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        session: Arc<RwLock<Session>>,
        request: &ModifySubscriptionRequest,
    ) -> SupportedMessage {
        let server_state = trace_write_lock!(server_state);
        let mut session = trace_write_lock!(session);

        let subscriptions = session.subscriptions_mut();
        let subscription_id = request.subscription_id;

        if !subscriptions.contains(subscription_id) {
            self.service_fault(
                &request.request_header,
                StatusCode::BadSubscriptionIdInvalid,
            )
        } else {
            let subscription = subscriptions.get_mut(subscription_id).unwrap();

            let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
                SubscriptionService::revise_subscription_values(
                    &server_state,
                    request.requested_publishing_interval,
                    request.requested_max_keep_alive_count,
                    request.requested_lifetime_count,
                );

            subscription.set_publishing_interval(revised_publishing_interval);
            subscription.set_max_keep_alive_count(revised_max_keep_alive_count);
            subscription.set_max_lifetime_count(revised_lifetime_count);
            subscription.set_priority(request.priority);
            subscription.reset_lifetime_counter();
            subscription.reset_keep_alive_counter();
            // ...max_notifications_per_publish??

            ModifySubscriptionResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                revised_publishing_interval,
                revised_lifetime_count,
                revised_max_keep_alive_count,
            }
            .into()
        }
    }

    /// Implementation of SetPublishingModeRequest service. See OPC Unified Architecture, Part 4 5.13.4
    pub fn set_publishing_mode(
        &self,
        session: Arc<RwLock<Session>>,
        request: &SetPublishingModeRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.subscription_ids) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut session = trace_write_lock!(session);
            let subscription_ids = request.subscription_ids.as_ref().unwrap();
            let results = {
                let publishing_enabled = request.publishing_enabled;
                let mut results = Vec::with_capacity(subscription_ids.len());
                let subscriptions = session.subscriptions_mut();
                for subscription_id in subscription_ids {
                    if let Some(subscription) = subscriptions.get_mut(*subscription_id) {
                        subscription.set_publishing_enabled(publishing_enabled);
                        subscription.reset_lifetime_counter();
                        results.push(StatusCode::Good);
                    } else {
                        results.push(StatusCode::BadSubscriptionIdInvalid);
                    }
                }
                Some(results)
            };
            let diagnostic_infos = None;
            SetPublishingModeResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results,
                diagnostic_infos,
            }
            .into()
        }
    }

    /// Handles a TransferSubscriptionsRequest
    pub fn transfer_subscriptions(
        &self,
        _session: Arc<RwLock<Session>>,
        request: &TransferSubscriptionsRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.subscription_ids) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let subscription_ids = request.subscription_ids.as_ref().unwrap();
            let results = {
                // TODO this is a stub. The real thing should look up subscriptions belonging to
                //  other sessions and transfer them across to this one.
                let results = subscription_ids
                    .iter()
                    .map(|_subscription_id| TransferResult {
                        status_code: StatusCode::BadSubscriptionIdInvalid,
                        available_sequence_numbers: None,
                    })
                    .collect::<Vec<TransferResult>>();
                Some(results)
            };
            let diagnostic_infos = None;
            TransferSubscriptionsResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results,
                diagnostic_infos,
            }
            .into()
        }
    }

    /// Handles a DeleteSubscriptionsRequest
    pub fn delete_subscriptions(
        &self,
        session: Arc<RwLock<Session>>,
        request: &DeleteSubscriptionsRequest,
    ) -> SupportedMessage {
        if is_empty_option_vec!(request.subscription_ids) {
            self.service_fault(&request.request_header, StatusCode::BadNothingToDo)
        } else {
            let mut session = trace_write_lock!(session);
            let subscription_ids = request.subscription_ids.as_ref().unwrap();
            let results = {
                let subscriptions = session.subscriptions_mut();
                // Attempt to remove each subscription
                let results = subscription_ids
                    .iter()
                    .map(|subscription_id| {
                        let subscription = subscriptions.remove(*subscription_id);
                        if subscription.is_some() {
                            StatusCode::Good
                        } else {
                            StatusCode::BadSubscriptionIdInvalid
                        }
                    })
                    .collect::<Vec<StatusCode>>();
                Some(results)
            };
            let diagnostic_infos = None;
            DeleteSubscriptionsResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                results,
                diagnostic_infos,
            }
            .into()
        }
    }

    /// Handles a PublishRequest. This is asynchronous, so the response will be sent later on.
    pub fn async_publish(
        &self,
        now: &DateTimeUtc,
        session: Arc<RwLock<Session>>,
        address_space: Arc<RwLock<AddressSpace>>,
        request_id: u32,
        request: &PublishRequest,
    ) -> Option<SupportedMessage> {
        trace!("--> Receive a PublishRequest {:?}", request);
        let mut session = trace_write_lock!(session);
        if session.subscriptions().is_empty() {
            Some(self.service_fault(&request.request_header, StatusCode::BadNoSubscription))
        } else {
            let address_space = trace_read_lock!(address_space);
            let request_header = request.request_header.clone();
            let result =
                session.enqueue_publish_request(now, request_id, request.clone(), &address_space);
            if let Err(error) = result {
                Some(self.service_fault(&request_header, error))
            } else {
                None
            }
        }
    }

    /// Handles a RepublishRequest
    pub fn republish(
        &self,
        session: Arc<RwLock<Session>>,
        request: &RepublishRequest,
    ) -> SupportedMessage {
        trace!("Republish {:?}", request);
        // Look for a matching notification message
        let mut session = trace_write_lock!(session);
        let result = session
            .subscriptions()
            .find_notification_message(request.subscription_id, request.retransmit_sequence_number);
        if let Ok(notification_message) = result {
            session.reset_subscription_lifetime_counter(request.subscription_id);
            let response = RepublishResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                notification_message,
            };
            response.into()
        } else {
            self.service_fault(&request.request_header, result.unwrap_err())
        }
    }

    /// This function takes the requested values passed in a create / modify and returns revised
    /// values that conform to the server's limits. For simplicity the return type is a tuple
    fn revise_subscription_values(
        server_state: &ServerState,
        requested_publishing_interval: Duration,
        requested_max_keep_alive_count: u32,
        requested_lifetime_count: u32,
    ) -> (Duration, u32, u32) {
        let revised_publishing_interval = f64::max(
            requested_publishing_interval,
            server_state.min_publishing_interval_ms,
        );
        let revised_max_keep_alive_count =
            if requested_max_keep_alive_count > server_state.max_keep_alive_count {
                server_state.max_keep_alive_count
            } else if requested_max_keep_alive_count == 0 {
                server_state.default_keep_alive_count
            } else {
                requested_max_keep_alive_count
            };
        // Lifetime count must exceed keep alive count by at least a multiple of
        let min_lifetime_count = revised_max_keep_alive_count * 3;
        let revised_lifetime_count = if requested_lifetime_count < min_lifetime_count {
            min_lifetime_count
        } else if requested_lifetime_count > server_state.max_lifetime_count {
            server_state.max_lifetime_count
        } else {
            requested_lifetime_count
        };
        (
            revised_publishing_interval,
            revised_max_keep_alive_count,
            revised_lifetime_count,
        )
    }
}
