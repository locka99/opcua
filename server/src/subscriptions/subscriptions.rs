use std::collections::{BTreeMap, VecDeque};

use time;

use opcua_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::{PublishRequest, PublishResponse, ServiceFault, ResponseHeader, NotificationMessage};

use DateTimeUtc;
use address_space::types::AddressSpace;
use subscriptions::{PublishRequestEntry, PublishResponseEntry};
use subscriptions::subscription::{Subscription, SubscriptionState, TickReason};

/// Incrementing sequence number
pub struct SequenceNumber {
    last_number: UInt32,
}

impl SequenceNumber {
    /// Sequence numbers wrap when they exceed this value
    const SEQUENCE_NUMBER_WRAPAROUND: u32 = 4294966271;

    pub fn new() -> SequenceNumber {
        SequenceNumber {
            last_number: 0
        }
    }

    /// Returns the next sequence number which is usually one more than the last one but can wrap
    pub fn next_number(&mut self) -> UInt32 {
        self.last_number += 1;
        // Sequence number should wrap if it exceeds this value - part 6
        if self.last_number > Self::SEQUENCE_NUMBER_WRAPAROUND {
            self.last_number = 1;
        }
        self.last_number
    }
}


/// The `Subscriptions` manages zero or more subscriptions, pairing publish requests coming from
/// the client with notifications coming from the subscriptions. Therefore the subscriptions has
/// an incoming queue of publish requests and an outgoing queue of publish responses. The transport
/// layer adds to the one and removes from the other.
///
/// Subscriptions are processed inside `tick()` which is called periodically from a timer. Each
/// tick produces notifications which are ready to publish via a transmission queue. Once a
/// notification is published, it is held in a retransmission queue until it is acknowledged by the
/// client, or purged.
pub struct Subscriptions {
    /// The publish request queue (requests by the client on the session)
    pub publish_request_queue: VecDeque<PublishRequestEntry>,
    /// The publish response queue
    pub publish_response_queue: VecDeque<PublishResponseEntry>,
    // Timeout period for requests in ms
    publish_request_timeout: i64,
    /// Subscriptions associated with the session
    subscriptions: BTreeMap<UInt32, Subscription>,
    /// Maximum number of publish requests
    max_publish_requests: usize,
    /// Maximum number of items in the retransmission queue
    max_retransmission_queue: usize,
    // Notifications waiting to be sent - Value is subscription id and notification message.
    transmission_queue: VecDeque<(UInt32, NotificationMessage)>,
    // Notifications that have been sent but have yet to be acknowledged (retransmission queue).
    // Key is sequence number. Value is subscription id and notification message
    retransmission_queue: BTreeMap<UInt32, (UInt32, NotificationMessage)>,
    /// The value that records the value of the sequence number used in a `NotificationMessage`.
    /// This value increments as each notification is added to the transmission queue and the value
    /// is stored in the notification. Sequence numbers wrap.
    sequence_number: SequenceNumber,
}

impl Subscriptions {
    pub fn new(max_publish_requests: usize, publish_request_timeout: i64) -> Subscriptions {
        Subscriptions {
            publish_request_queue: VecDeque::with_capacity(max_publish_requests),
            publish_response_queue: VecDeque::with_capacity(max_publish_requests),
            publish_request_timeout,
            subscriptions: BTreeMap::new(),
            max_publish_requests,
            sequence_number: SequenceNumber::new(),
            max_retransmission_queue: max_publish_requests * 2,
            transmission_queue: VecDeque::new(),
            retransmission_queue: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn retransmission_queue(&mut self) -> &mut BTreeMap<UInt32, (UInt32, NotificationMessage)> {
        &mut self.retransmission_queue
    }

    /// Places a new publish request onto the queue of publish requests.
    ///
    /// If the queue is full this call will pop the oldest and generate a service fault
    /// for that before pushing the new one.
    pub fn enqueue_publish_request(&mut self, _: &AddressSpace, request_id: UInt32, request: PublishRequest) -> Result<(), StatusCode> {
        // Acknowledge anything to be acknowledged
        let _ = self.process_subscription_acknowledgements(&request);

        // Check if we have too many requests already
        if self.publish_request_queue.len() >= self.max_publish_requests {
            error!("Too many publish requests {} for capacity {}, throwing oldest away", self.publish_request_queue.len(), self.max_publish_requests);
            let _oldest_publish_request = self.publish_request_queue.pop_back().unwrap();
            Err(BadTooManyPublishRequests)
        } else {
            // Add to the start of the queue - older items are popped from the end
            self.publish_request_queue.push_front(PublishRequestEntry {
                request_id,
                request,
            });
            Ok(())
        }
    }

    pub fn dequeue_publish_request(&mut self) -> Option<PublishRequestEntry> {
        self.publish_request_queue.pop_back()
    }

    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.subscriptions.len()
    }

    pub fn contains(&self, subscription_id: UInt32) -> bool {
        self.subscriptions.contains_key(&subscription_id)
    }

    pub fn insert(&mut self, subscription_id: UInt32, subscription: Subscription) {
        self.subscriptions.insert(subscription_id, subscription);
    }

    pub fn remove(&mut self, subscription_id: UInt32) -> Option<Subscription> {
        self.subscriptions.remove(&subscription_id)
    }

    pub fn get_mut(&mut self, subscription_id: UInt32) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&subscription_id)
    }

    /// The tick causes the subscription manager to iterate through individual subscriptions calling tick
    /// on each in order of priority. In each case this could generate data change notifications. Data change
    /// notifications will be attached to the next available publish response and queued for sending
    /// to the client.
    pub fn tick(&mut self, now: &DateTimeUtc, address_space: &AddressSpace, tick_reason: TickReason) -> Result<(), StatusCode> {
        let subscription_ids = {
            let mut subscription_priority: Vec<(u32, u8)> = self.subscriptions.values().map(|v| (v.subscription_id, v.priority)).collect();
            subscription_priority.sort_by(|s1, s2| s1.1.cmp(&s2.1));
            subscription_priority.iter().map(|s| s.0).collect::<Vec<u32>>()
        };

        // Iterate through all subscriptions. If there is a publish request it will be used to
        // acknowledge notifications and the response to return new notifications.

        let mut publish_request_len = self.publish_request_queue.len();

        // Now tick over the subscriptions
        subscription_ids.iter().for_each(|subscription_id| {
            let subscription_state = {
                let subscription = self.subscriptions.get(subscription_id).unwrap();
                subscription.state
            };
            if subscription_state == SubscriptionState::Closed {
                // Subscription is dead so remove it
                self.subscriptions.remove(&subscription_id);
            } else {
                let notification_message = {
                    let publishing_req_queued = publish_request_len > 0;
                    let subscription = self.subscriptions.get_mut(subscription_id).unwrap();
                    // Now tick the subscription to see if it has any notifications. If there are
                    // notifications then the publish response will be associated with his subscription
                    // and ready to go.
                    subscription.tick(address_space, tick_reason, publishing_req_queued, now)
                };
                if let Some(mut notification_message) = notification_message {
                    trace!("Subscription {} produced a notification message", subscription_id);
                    // Give the notification message a sequence number
                    notification_message.sequence_number = self.sequence_number.next_number();
                    // Push onto the transmission queue
                    self.transmission_queue.push_front((*subscription_id, notification_message));
                    if publish_request_len > 0 {
                        publish_request_len -= 1;
                    }
                }
            }
        });

        // Iterate through notifications in the transmission making publish responses until either
        // the transmission queue or publish request queue becomes empty

        while !self.transmission_queue.is_empty() && !self.publish_request_queue.is_empty() {
            trace!("Pairing a notification from the transmission queue to a publish request");
            let publish_request = self.publish_request_queue.pop_back().unwrap();

            // Get the oldest notification to send
            let (subscription_id, notification_message) = self.transmission_queue.pop_back().unwrap();

            // Search the transmission queue for more notifications from this same subscription
            let more_notifications = self.more_notifications(subscription_id);

            // Get a list of available sequence numbers
            let available_sequence_numbers = self.available_sequence_numbers(subscription_id);

            // The notification to be sent is now put into the retransmission queue
            self.retransmission_queue.insert(notification_message.sequence_number, (subscription_id, notification_message.clone()));

            let response = self.make_publish_response(&publish_request, subscription_id, now, notification_message, more_notifications, available_sequence_numbers);
            self.publish_response_queue.push_front(response);
        }

        // Clean up the retransmission queue
        self.remove_old_unknowledged_notifications();

        Ok(())
    }

    /// Iterates through the existing queued publish requests and creates a timeout
    /// publish response any that have expired.
    pub fn expire_stale_publish_requests(&mut self, now: &DateTimeUtc) {
        if self.publish_request_queue.is_empty() {
            return;
        }

        let mut publish_responses = VecDeque::with_capacity(self.publish_request_queue.len());

        // Remove publish requests that have expired
        let publish_request_timeout = self.publish_request_timeout;
        self.publish_request_queue.retain(|ref request| {
            let request_header = &request.request.request_header;
            let timestamp: DateTimeUtc = request_header.timestamp.clone().into();
            let timeout = if request_header.timeout_hint > 0 && (request_header.timeout_hint as i64) < publish_request_timeout {
                request_header.timeout_hint as i64
            } else {
                publish_request_timeout
            };
            let timeout_d = time::Duration::milliseconds(timeout);
            // The request has timed out if the timestamp plus hint exceeds the input time
            let expiration_time = timestamp + timeout_d;
            if *now >= expiration_time {
                debug!("Publish request {} has expired - timestamp = {:?}, expiration hint = {}, expiration time = {:?}, time now = {:?}, ", request_header.request_handle, timestamp, timeout, expiration_time, now);
                publish_responses.push_front(PublishResponseEntry {
                    request_id: request.request_id,
                    response: SupportedMessage::ServiceFault(ServiceFault {
                        response_header: ResponseHeader::new_timestamped_service_result(DateTime::now(), &request.request.request_header, BadTimeout),
                    }),
                });
                false
            } else {
                true
            }
        });
        // Queue responses for each expired request
        self.publish_response_queue.append(&mut publish_responses);
    }

    /// Deletes the acknowledged notifications, returning a list of status code for each according
    /// to whether it was found or not.
    ///
    /// Good - deleted notification
    /// BadSubscriptionIdInvalid - Subscription doesn't exist
    /// BadSequenceNumberUnknown - Sequence number doesn't exist
    ///
    fn process_subscription_acknowledgements(&mut self, request: &PublishRequest) -> Option<Vec<StatusCode>> {
        trace!("Processing subscription acknowledgements");
        if let Some(ref subscription_acknowledgements) = request.subscription_acknowledgements {
            let results = subscription_acknowledgements.iter().map(|subscription_acknowledgement| {
                let subscription_id = subscription_acknowledgement.subscription_id;
                let sequence_number = subscription_acknowledgement.sequence_number;
                // Check the subscription id exists
                if self.subscriptions.get(&subscription_id).is_some() {
                    // Clear notification by its sequence number
                    if self.retransmission_queue.remove(&sequence_number).is_some() {
                        Good
                    } else {
                        error!("Can't find acknowledged notification with sequence number {}", sequence_number);
                        BadSequenceNumberUnknown
                    }
                } else {
                    error!("Can't find acknowledged notification subscription id {}", subscription_id);
                    BadSubscriptionIdInvalid
                }
            }).collect();
            Some(results)
        } else {
            None
        }
    }

    /// Searches the transmission queue to see if there are more notifications for the specified
    /// subscription id
    fn more_notifications(&self, subscription_id: UInt32) -> bool {
        // At least one match means more notifications
        self.transmission_queue.iter().find(|v| v.0 == subscription_id).is_some()
    }

    /// Returns the array of available sequence numbers for the specified subscription
    fn available_sequence_numbers(&self, subscription_id: UInt32) -> Option<Vec<UInt32>> {
        if self.retransmission_queue.is_empty() {
            None
        } else {
            // Find the notifications matching this subscription id in the retransmission queue
            let sequence_numbers: Vec<UInt32> = self.retransmission_queue.iter().filter(|&(_, v)| v.0 == subscription_id).map(|(k, _)| *k).collect();
            if sequence_numbers.is_empty() {
                None
            } else {
                Some(sequence_numbers)
            }
        }
    }

    fn make_publish_response(&self, publish_request: &PublishRequestEntry, subscription_id: UInt32, now: &DateTimeUtc, notification_message: NotificationMessage, more_notifications: bool, available_sequence_numbers: Option<Vec<UInt32>>) -> PublishResponseEntry {
        let now = DateTime::from(now.clone());
        PublishResponseEntry {
            request_id: publish_request.request_id,
            response: SupportedMessage::PublishResponse(PublishResponse {
                response_header: ResponseHeader::new_timestamped_service_result(now, &publish_request.request.request_header, Good),
                subscription_id,
                available_sequence_numbers,
                more_notifications,
                notification_message,
                results: None,
                diagnostic_infos: None,
            }),
        }
    }

    /// Finds a notification message in the retransmission queue matching the supplied subscription id
    /// and sequence number. Returns `BadNoSubscription` or `BadMessageNotAvailable` if a matching
    /// notification is not found.
    pub fn find_notification_message(&self, subscription_id: UInt32, sequence_number: UInt32) -> Result<NotificationMessage, StatusCode> {
        // Look for the subscription
        if self.subscriptions.get(&subscription_id).is_some() {
            // Look for the sequence number
            if let Some(ref notification_message) = self.retransmission_queue.get(&sequence_number) {
                Ok(notification_message.1.clone())
            } else {
                Err(StatusCode::BadMessageNotAvailable)
            }
        } else {
            Err(StatusCode::BadNoSubscription)
        }
    }

    /// Purges notifications waiting for acknowledgement if they exceed the max retransmission queue
    /// size.
    fn remove_old_unknowledged_notifications(&mut self) {
        if self.retransmission_queue.len() <= self.max_retransmission_queue {
            return;
        }

        // Compare number of items in retransmission queue to max permissible and remove the older
        // notifications.
        let remove_count = self.retransmission_queue.len() - self.max_retransmission_queue;
        let mut sequence_numbers_to_remove = Vec::with_capacity(remove_count);

        // BTree means these should iterate in order of insertion, i.e. oldest first
        for (k, _) in &self.retransmission_queue {
            if sequence_numbers_to_remove.len() > remove_count {
                break;
            }
            sequence_numbers_to_remove.push(*k);
        }

        // Remove expired sequence numbers from the retransmission queue
        for sequence_number in sequence_numbers_to_remove {
            let _ = self.retransmission_queue.remove(&sequence_number);
        }
    }
}