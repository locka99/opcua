use std::collections::{HashMap, HashSet};

use time;
use chrono;

use opcua_types::*;

use DateTimeUTC;
use address_space::types::AddressSpace;
use subscriptions::subscription::{Subscription, SubscriptionState};
use server::ServerState;

const MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE: usize = 100;
const MAX_PUBLISH_REQUESTS: usize = 200;
const MAX_REQUEST_TIMEOUT: i64 = 30000;

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

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

/// Structure that captures diagnostics information for the session
#[derive(Clone)]
pub struct SessionDiagnostics {}

impl SessionDiagnostics {
    pub fn new() -> SessionDiagnostics {
        SessionDiagnostics {}
    }
}

/// Session state is anything associated with the session at the message / service level
pub struct Session {
    /// Subscriptions associated with the session
    pub subscriptions: HashMap<UInt32, Subscription>,
    /// The publish requeust queue (requests by the client on the session)
    pub publish_request_queue: Vec<PublishRequestEntry>,
    /// The session identifier
    pub session_id: NodeId,
    /// Indicates if the session has received an ActivateSession
    pub activated: bool,
    /// Flag to indicate session should be terminated
    pub terminate_session: bool,
    /// Security policy
    pub security_policy_uri: String,
    /// Client's certificate
    pub client_certificate: ByteString,
    /// Authentication token for the session
    pub authentication_token: NodeId,
    /// Session nonce
    pub session_nonce: ByteString,
    /// Session timeout
    pub session_timeout: Double,
    /// User identity token
    pub user_identity: Option<ExtensionObject>,
    /// Negotiated max request message size
    pub max_request_message_size: UInt32,
    /// Negotiated max response message size
    pub max_response_message_size: UInt32,
    /// Endpoint url for this session
    pub endpoint_url: UAString,
    /// Diagnostics associated with the session
    pub diagnostics: SessionDiagnostics,
    /// Internal value used to create new session ids.
    last_session_id: UInt32,
}

impl Session {
    pub fn new() -> Session {
        Session {
            subscriptions: HashMap::new(),
            publish_request_queue: Vec::with_capacity(MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE),
            session_id: NodeId::null(),
            activated: false,
            terminate_session: false,
            client_certificate: ByteString::null(),
            security_policy_uri: String::new(),
            authentication_token: NodeId::null(),
            session_nonce: ByteString::null(),
            session_timeout: 0f64,
            user_identity: None,
            max_request_message_size: 0,
            max_response_message_size: 0,
            endpoint_url: UAString::null(),
            diagnostics: SessionDiagnostics::new(),
            last_session_id: 0,
        }
    }

    pub fn next_session_id(&mut self) -> NodeId {
        self.last_session_id += 1;
        NodeId::new_numeric(1, self.last_session_id as u64)
    }

    pub fn enqueue_publish_request(&mut self, server_state: &mut ServerState, request_id: UInt32, request: PublishRequest) -> Result<Option<Vec<PublishResponseEntry>>, StatusCode> {
        let max_publish_requests = MAX_PUBLISH_REQUESTS;
        if self.publish_request_queue.len() >= max_publish_requests {
            error!("Too many publish requests, throwing it away");
            Err(BAD_TOO_MANY_PUBLISH_REQUESTS)
        } else {
            trace!("Sending a tick to subscriptions to deal with the request");
            self.publish_request_queue.insert(0, PublishRequestEntry {
                request_id: request_id,
                request: request,
            });
            let address_space = server_state.address_space.lock().unwrap();
            Ok(self.tick_subscriptions(true, &address_space))
        }
    }

    /// Iterate all subscriptions calling tick on each. Note this could potentially be done to run in parallel
    /// assuming the action to clean dead subscriptions was a join done after all ticks had completed.
    pub fn tick_subscriptions(&mut self, receive_publish_request: bool, address_space: &AddressSpace) -> Option<Vec<PublishResponseEntry>> {
        let now = chrono::UTC::now();

        let mut request_response_results = Vec::with_capacity(self.publish_request_queue.len());
        let mut dead_subscriptions: Vec<u32> = Vec::with_capacity(self.subscriptions.len());

        // Iterate through all subscriptions. If there is a publish request it will be used to
        // acknowledge notifications and the response to return new notifications.
        for (subscription_id, subscription) in self.subscriptions.iter_mut() {
            // Dead subscriptions will be removed at the end
            if subscription.state == SubscriptionState::Closed {
                dead_subscriptions.push(*subscription_id);
            } else {
                let publish_request = self.publish_request_queue.pop();
                let publishing_req_queued = self.publish_request_queue.len() > 0 || publish_request.is_some();

                let (publish_response, update_state_result) = subscription.tick(address_space, receive_publish_request, &publish_request, publishing_req_queued, &now);
                if let Some(update_state_result) = update_state_result {
                    if let Some(publish_response) = publish_response {
                        if publish_request.is_none() {
                            panic!("Should not be publishing a response without a request, state = {:?}", update_state_result);
                        }
                        // debug!("Queuing a publish response {:?}", publish_response);
                        request_response_results.push((publish_request.unwrap(), publish_response));
                    } else if publish_request.is_some() {
                        // Put the request back
                        self.publish_request_queue.push(publish_request.unwrap());
                    }
                }
            }
        }

        // Remove dead subscriptions
        for subscription_id in dead_subscriptions {
            self.subscriptions.remove(&subscription_id);
        }

        if request_response_results.is_empty() {
            None
        } else {
            let mut results = Vec::with_capacity(request_response_results.len());
            // Handle acknowledgements
            for mut rr in request_response_results {
                if let SupportedMessage::PublishResponse(ref mut response) = rr.1.response {
                    response.results = self.process_subscription_acknowledgements(&rr.0);
                }
                results.push(rr.1);
            }
            Some(results)
        }
    }

    /// Iterates through the existing queued publish requests and creates a timeout
    /// publish response any that have expired.
    pub fn expire_stale_publish_requests(&mut self, now: &DateTimeUTC) -> Option<Vec<PublishResponseEntry>> {
        if self.publish_request_queue.is_empty() {
            return None;
        }

        // Look for publish requests that have expired
        let mut expired_request_handles = HashSet::with_capacity(self.publish_request_queue.len());
        let mut expired_requests = Vec::with_capacity(self.publish_request_queue.len());

        for request in self.publish_request_queue.iter() {
            let request_header = &request.request.request_header;
            let timestamp: DateTimeUTC = request_header.timestamp.as_chrono();
            let timeout = if request_header.timeout_hint > 0 && (request_header.timeout_hint as i64) < MAX_REQUEST_TIMEOUT {
                request_header.timeout_hint as i64
            } else {
                MAX_REQUEST_TIMEOUT
            };
            let timeout_d = time::Duration::milliseconds(timeout);
            // The request has timed out if the timestamp plus hint exceeds the input time
            let expiration_time = timestamp + timeout_d;
            if *now >= expiration_time {
                debug!("Publish request {} has expired - timestamp = {:?}, expiration hint = {}, expiration time = {:?}, time now = {:?}, ", request_header.request_handle, timestamp, timeout, expiration_time, now);
                expired_request_handles.insert(request_header.request_handle);
                expired_requests.push(request.clone());
            }
        }

        if expired_request_handles.is_empty() {
            return None;
        }

        // Remove the expired requests (if any)
        self.publish_request_queue.retain(|ref r| {
            !expired_request_handles.contains(&r.request.request_header.request_handle)
        });

        // Make publish responses for each expired request
        let mut publish_responses = Vec::with_capacity(expired_requests.len());
        for expired_request in expired_requests {
            let now = DateTime::from_chrono(now);
            publish_responses.push(PublishResponseEntry {
                request_id: expired_request.request_id,
                response: SupportedMessage::ServiceFault(ServiceFault {
                    response_header: ResponseHeader::new_timestamped_service_result(now.clone(), &expired_request.request.request_header, BAD_REQUEST_TIMEOUT),
                }),
            });
        }
        if !publish_responses.is_empty() {
            Some(publish_responses)
        } else {
            None
        }
    }

    fn process_subscription_acknowledgements(&mut self, request: &PublishRequestEntry) -> Option<Vec<StatusCode>> {
        trace!("Processing subscription acknowledgements");
        //
        /// Deletes the acknowledged notifications, returning a list of status code for each according
        /// to whether it was found or not.
        ///
        /// GOOD - deleted notification
        /// BAD_SUBSCRIPTION_ID_INVALID - Subscription doesn't exist
        /// BAD_SEQUENCE_NUMBER_UNKNOWN - Sequence number doesn't exist
        ///
        let request = &request.request;
        if request.subscription_acknowledgements.is_some() {
            let subscription_acknowledgements = request.subscription_acknowledgements.as_ref().unwrap();
            let mut results: Vec<StatusCode> = Vec::with_capacity(subscription_acknowledgements.len());
            for subscription_acknowledgement in subscription_acknowledgements {
                let subscription_id = subscription_acknowledgement.subscription_id;
                let subscription = self.subscriptions.get_mut(&subscription_id);
                let result = if subscription.is_none() {
                    BAD_SUBSCRIPTION_ID_INVALID
                } else {
                    subscription.unwrap().delete_acked_notification_msg(subscription_acknowledgement)
                };
                results.push(result);
            }
            Some(results)
        } else {
            None
        }
    }
}
