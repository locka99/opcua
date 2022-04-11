// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::collections::{BTreeMap, VecDeque};

use crate::types::{
    service_types::{NotificationMessage, PublishRequest, PublishResponse, ServiceFault},
    status_code::StatusCode,
    *,
};

use crate::server::{
    address_space::types::AddressSpace,
    subscriptions::{
        subscription::{Subscription, TickReason},
        PublishRequestEntry, PublishResponseEntry,
    },
};

/// The `Subscriptions` manages zero or more subscriptions, pairing publish requests coming from
/// the client with notifications coming from the subscriptions. Therefore the subscriptions has
/// an incoming queue of publish requests and an outgoing queue of publish responses. The transport
/// layer adds to the one and removes from the other.
///
/// Subscriptions are processed inside `tick()` which is called periodically from a timer. Each
/// tick produces notifications which are ready to publish via a transmission queue. Once a
/// notification is published, it is held in a retransmission queue until it is acknowledged by the
/// client, or purged.
pub(crate) struct Subscriptions {
    /// The publish request queue (requests by the client on the session)
    publish_request_queue: VecDeque<PublishRequestEntry>,
    /// The publish response queue arranged oldest to latest
    publish_response_queue: VecDeque<PublishResponseEntry>,
    // Timeout period for requests in ms
    publish_request_timeout: i64,
    /// Subscriptions associated with the session
    subscriptions: BTreeMap<u32, Subscription>,
    // Notifications waiting to be sent - Value is subscription id and notification message.
    transmission_queue: VecDeque<(u32, PublishRequestEntry, NotificationMessage)>,
    // Notifications that have been sent but have yet to be acknowledged (retransmission queue).
    // Key is (subscription_id, sequence_number). Value is notification message.
    retransmission_queue: BTreeMap<(u32, u32), NotificationMessage>,
}

#[derive(Serialize)]
pub struct Metrics {
    pub subscriptions: Vec<Subscription>,
    pub publish_request_queue_len: usize,
    pub publish_response_queue_len: usize,
    pub transmission_queue_len: usize,
    pub retransmission_queue_len: usize,
}

impl Subscriptions {
    pub fn new(max_subscriptions: usize, publish_request_timeout: i64) -> Subscriptions {
        let max_publish_requests = if max_subscriptions > 0 {
            2 * max_subscriptions
        } else {
            100
        };
        Subscriptions {
            publish_request_queue: VecDeque::with_capacity(max_publish_requests),
            publish_response_queue: VecDeque::with_capacity(max_publish_requests),
            publish_request_timeout,
            subscriptions: BTreeMap::new(),
            transmission_queue: VecDeque::with_capacity(max_publish_requests),
            retransmission_queue: BTreeMap::new(),
        }
    }

    pub(crate) fn metrics(&self) -> Metrics {
        // Subscriptions
        let subscriptions = self
            .subscriptions()
            .iter()
            .map(|subscription_pair| {
                let mut subscription = subscription_pair.1.clone();
                subscription.set_diagnostics_on_drop(false);
                subscription
            })
            .collect();
        Metrics {
            subscriptions,
            publish_request_queue_len: self.publish_request_queue.len(),
            publish_response_queue_len: self.publish_response_queue.len(),
            transmission_queue_len: self.transmission_queue.len(),
            retransmission_queue_len: self.retransmission_queue.len(),
        }
    }

    #[cfg(test)]
    pub(crate) fn publish_request_queue(&mut self) -> &mut VecDeque<PublishRequestEntry> {
        &mut self.publish_request_queue
    }

    #[cfg(test)]
    pub(crate) fn publish_response_queue(&mut self) -> &mut VecDeque<PublishResponseEntry> {
        &mut self.publish_response_queue
    }

    #[cfg(test)]
    pub(crate) fn retransmission_queue(
        &mut self,
    ) -> &mut BTreeMap<(u32, u32), NotificationMessage> {
        &mut self.retransmission_queue
    }

    /// Takes the publish responses which are queued for the client and returns them to the caller,
    /// or returns None if there are none to process.
    pub fn take_publish_responses(&mut self) -> Option<VecDeque<PublishResponseEntry>> {
        if self.publish_response_queue.is_empty() {
            None
        } else {
            // Take the publish responses from the subscriptions
            let mut publish_responses = VecDeque::with_capacity(self.publish_response_queue.len());
            publish_responses.append(&mut self.publish_response_queue);
            Some(publish_responses)
        }
    }

    /// Returns the number of maxmimum publish requests allowable for the current number of subscriptions
    pub fn max_publish_requests(&self) -> usize {
        // Allow for two requests per subscription
        self.subscriptions.len() * 2
    }

    /// Places a new publish request onto the queue of publish requests.
    ///
    /// If the queue is full this call will pop the oldest and generate a service fault
    /// for that before pushing the new one.
    pub(crate) fn enqueue_publish_request(
        &mut self,
        now: &DateTimeUtc,
        request_id: u32,
        request: PublishRequest,
        address_space: &AddressSpace,
    ) -> Result<(), StatusCode> {
        // Check if we have too  requests waiting already
        let max_publish_requests = self.max_publish_requests();
        if self.publish_request_queue.len() >= max_publish_requests {
            // Tick to trigger publish, maybe remove a request to make space for new one
            let _ = self.tick(now, address_space, TickReason::ReceivePublishRequest);
        }

        // Enqueue request or return error
        if self.publish_request_queue.len() >= max_publish_requests {
            error!(
                "Too many publish requests {} for capacity {}",
                self.publish_request_queue.len(),
                max_publish_requests
            );
            Err(StatusCode::BadTooManyPublishRequests)
        } else {
            // Add to the front of the queue - older items are popped from the back
            let results = self.process_subscription_acknowledgements(&request);
            self.publish_request_queue.push_front(PublishRequestEntry {
                request_id,
                request,
                results,
            });
            // Tick to trigger publish
            self.tick(now, address_space, TickReason::ReceivePublishRequest)
        }
    }

    /// Tests if there are no subscriptions/
    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
    }

    /// Returns the length of subscriptions.
    pub fn len(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns a reference to the collection holding the subscriptions.
    pub fn subscriptions(&self) -> &BTreeMap<u32, Subscription> {
        &self.subscriptions
    }

    /// Tests if the subscriptions contain the supplied subscription id.
    pub fn contains(&self, subscription_id: u32) -> bool {
        self.subscriptions.contains_key(&subscription_id)
    }

    pub fn insert(&mut self, subscription_id: u32, subscription: Subscription) {
        self.subscriptions.insert(subscription_id, subscription);
    }

    pub fn remove(&mut self, subscription_id: u32) -> Option<Subscription> {
        self.subscriptions.remove(&subscription_id)
    }

    pub fn get_mut(&mut self, subscription_id: u32) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&subscription_id)
    }

    /// The tick causes the subscription manager to iterate through individual subscriptions calling tick
    /// on each in order of priority. In each case this could generate data change notifications. Data change
    /// notifications will be attached to the next available publish response and queued for sending
    /// to the client.
    pub(crate) fn tick(
        &mut self,
        now: &DateTimeUtc,
        address_space: &AddressSpace,
        tick_reason: TickReason,
    ) -> Result<(), StatusCode> {
        let subscription_ids = {
            // Sort subscriptions by priority
            let mut subscription_priority: Vec<(u32, u8)> = self
                .subscriptions
                .values()
                .map(|v| (v.subscription_id(), v.priority()))
                .collect();
            subscription_priority.sort_by(|s1, s2| s1.1.cmp(&s2.1));
            subscription_priority
                .iter()
                .map(|s| s.0)
                .collect::<Vec<u32>>()
        };

        // Iterate through all subscriptions. If there is a publish request it will be used to
        // acknowledge notifications and the response to return new notifications.

        // Now tick over the subscriptions
        for subscription_id in subscription_ids {
            let publishing_req_queued = !self.publish_request_queue.is_empty();
            let subscription = self.subscriptions.get_mut(&subscription_id).unwrap();

            // Now tick the subscription to see if it has any notifications. If there are
            // notifications then the publish response will be associated with his subscription
            // and ready to go.
            subscription.tick(now, address_space, tick_reason, publishing_req_queued);

            // Process any notifications
            loop {
                if !self.publish_request_queue.is_empty() {
                    if let Some(notification_message) = subscription.take_notification() {
                        let publish_request = self.publish_request_queue.pop_back().unwrap();
                        // Consume the publish request and queue the notification onto the transmission queue
                        self.transmission_queue.push_front((
                            subscription_id,
                            publish_request,
                            notification_message,
                        ));
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            // Remove the subscription if it is done
            if subscription.ready_to_remove() {
                self.subscriptions.remove(&subscription_id);
            }
        }

        // Iterate through notifications from oldest to latest in the transmission making publish
        // responses.
        while !self.transmission_queue.is_empty() {
            // Get the oldest notification to send
            let (subscription_id, publish_request, notification_message) =
                self.transmission_queue.pop_back().unwrap();

            // Search the transmission queue for more notifications from this same subscription
            let more_notifications = self.more_notifications(subscription_id);

            // Get a list of available sequence numbers
            let available_sequence_numbers = self.available_sequence_numbers(subscription_id);

            // The notification to be sent is now put into the retransmission queue
            self.retransmission_queue.insert(
                (subscription_id, notification_message.sequence_number),
                notification_message.clone(),
            );

            // Enqueue a publish response
            let response = self.make_publish_response(
                publish_request,
                subscription_id,
                now,
                notification_message,
                more_notifications,
                available_sequence_numbers,
            );
            self.publish_response_queue.push_back(response);
        }

        // Clean up the retransmission queue
        self.remove_old_unacknowledged_notifications();

        Ok(())
    }

    /// Iterates through the existing queued publish requests and creates a timeout
    /// publish response any that have expired.
    pub fn expire_stale_publish_requests(&mut self, now: &DateTimeUtc) {
        if self.publish_request_queue.is_empty() {
            return;
        }

        // Remove publish requests that have expired
        let publish_request_timeout = self.publish_request_timeout;

        // Create timeout responses for each expired publish request
        let mut expired_publish_responses =
            VecDeque::with_capacity(self.publish_request_queue.len());

        self.publish_request_queue.retain(|request| {
            let request_header = &request.request.request_header;
            let request_timestamp: DateTimeUtc = request_header.timestamp.into();
            let publish_request_timeout = time::Duration::milliseconds(if request_header.timeout_hint > 0 && (request_header.timeout_hint as i64) < publish_request_timeout {
                request_header.timeout_hint as i64
            } else {
                publish_request_timeout
            });
            // The request has timed out if the timestamp plus hint exceeds the input time
            if now.signed_duration_since(request_timestamp) > publish_request_timeout {
                debug!("Publish request {} has expired - timestamp = {:?}, expiration hint = {}, publish timeout = {:?}, time now = {:?}, ", request_header.request_handle, request_timestamp, request_timestamp, publish_request_timeout, now);
                expired_publish_responses.push_front(PublishResponseEntry {
                    request_id: request.request_id,
                    response: ServiceFault {
                        response_header: ResponseHeader::new_timestamped_service_result(DateTime::now(), &request.request.request_header, StatusCode::BadTimeout),
                    }.into(),
                });
                false
            } else {
                true
            }
        });
        // Queue responses for each expired request
        self.publish_response_queue
            .append(&mut expired_publish_responses);
    }

    /// Deletes the acknowledged notifications, returning a list of status code for each according
    /// to whether it was found or not.
    ///
    /// Good - deleted notification
    /// BadSubscriptionIdInvalid - Subscription doesn't exist
    /// BadSequenceNumberUnknown - Sequence number doesn't exist
    ///
    fn process_subscription_acknowledgements(
        &mut self,
        request: &PublishRequest,
    ) -> Option<Vec<StatusCode>> {
        trace!("Processing subscription acknowledgements");
        if let Some(ref subscription_acknowledgements) = request.subscription_acknowledgements {
            let results = subscription_acknowledgements.iter()
                .map(|subscription_acknowledgement| {
                    let subscription_id = subscription_acknowledgement.subscription_id;
                    let sequence_number = subscription_acknowledgement.sequence_number;
                    // Check the subscription id exists
                    if self.subscriptions.contains_key(&subscription_id) {
                        // Clear notification by its sequence number
                        if self.retransmission_queue.remove(&(subscription_id, sequence_number)).is_some() {
                            trace!("Removing subscription {} sequence number {} from retransmission queue", subscription_id, sequence_number);
                            StatusCode::Good
                        } else {
                            error!("Cannot find acknowledged notification with sequence number {}", sequence_number);
                            StatusCode::BadSequenceNumberUnknown
                        }
                    } else {
                        error!("Cannot find acknowledged notification subscription id {}", subscription_id);
                        StatusCode::BadSubscriptionIdInvalid
                    }
                })
                .collect();
            Some(results)
        } else {
            None
        }
    }

    /// Searches the transmission queue to see if there are more notifications for the specified
    /// subscription id
    fn more_notifications(&self, subscription_id: u32) -> bool {
        // At least one match means more notifications
        self.transmission_queue
            .iter()
            .any(|v| v.0 == subscription_id)
    }

    /// Returns the array of available sequence numbers in the retransmission queue for the specified subscription
    fn available_sequence_numbers(&self, subscription_id: u32) -> Option<Vec<u32>> {
        if self.retransmission_queue.is_empty() {
            None
        } else {
            // Find the notifications matching this subscription id in the retransmission queue
            let sequence_numbers: Vec<u32> = self
                .retransmission_queue
                .iter()
                .filter(|&(k, _)| k.0 == subscription_id)
                .map(|(k, _)| k.1)
                .collect();
            if sequence_numbers.is_empty() {
                None
            } else {
                Some(sequence_numbers)
            }
        }
    }

    fn make_publish_response(
        &self,
        publish_request: PublishRequestEntry,
        subscription_id: u32,
        now: &DateTimeUtc,
        notification_message: NotificationMessage,
        more_notifications: bool,
        available_sequence_numbers: Option<Vec<u32>>,
    ) -> PublishResponseEntry {
        let now = DateTime::from(*now);
        PublishResponseEntry {
            request_id: publish_request.request_id,
            response: PublishResponse {
                response_header: ResponseHeader::new_timestamped_service_result(
                    now,
                    &publish_request.request.request_header,
                    StatusCode::Good,
                ),
                subscription_id,
                available_sequence_numbers,
                more_notifications,
                notification_message,
                results: publish_request.results,
                diagnostic_infos: None,
            }
            .into(),
        }
    }

    /// Finds a notification message in the retransmission queue matching the supplied subscription id
    /// and sequence number. Returns `BadSubscriptionIdInvalid` or `BadMessageNotAvailable` if a matching
    /// notification is not found.
    pub fn find_notification_message(
        &self,
        subscription_id: u32,
        sequence_number: u32,
    ) -> Result<NotificationMessage, StatusCode> {
        // Look for the subscription
        if self.subscriptions.get(&subscription_id).is_some() {
            // Look for the sequence number
            if let Some(notification_message) = self
                .retransmission_queue
                .get(&(subscription_id, sequence_number))
            {
                Ok((*notification_message).clone())
            } else {
                Err(StatusCode::BadMessageNotAvailable)
            }
        } else {
            Err(StatusCode::BadSubscriptionIdInvalid)
        }
    }

    fn remove_notifications(&mut self, sequence_nrs_to_remove: &[(u32, u32)]) {
        sequence_nrs_to_remove.iter().for_each(|n| {
            trace!(
                "Removing notification for subscription {}, sequence nr {}",
                n.0,
                n.1
            );
            let _ = self.retransmission_queue.remove(n);
        });
    }

    /// Purges notifications waiting for acknowledgement if they are stale or the max permissible
    /// is exceeded.
    fn remove_old_unacknowledged_notifications(&mut self) {
        // Strip out notifications for subscriptions that no longer exist
        let sequence_nrs_to_remove = self
            .retransmission_queue
            .iter()
            .filter(|(k, _)| !self.subscriptions.contains_key(&k.0))
            .map(|(k, _)| *k)
            .collect::<Vec<_>>();
        self.remove_notifications(&sequence_nrs_to_remove);

        // Compare number of items in retransmission queue to max permissible and remove the older
        // notifications.
        let max_retransmission_queue = self.max_publish_requests() * 2;
        if self.retransmission_queue.len() > max_retransmission_queue {
            let remove_count = self.retransmission_queue.len() - max_retransmission_queue;
            let sequence_nrs_to_remove = self
                .retransmission_queue
                .iter()
                .take(remove_count)
                .map(|(k, _)| *k)
                .collect::<Vec<_>>();
            self.remove_notifications(&sequence_nrs_to_remove);
        }
    }
}
