use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use time;

use opcua_core::prelude::*;

use DateTimeUTC;
use subscriptions::*;

const MAX_PUBLISH_REQUESTS: usize = 10;

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

/// Session state is anything associated with the session at the message / service level
#[derive(Clone)]
pub struct SessionState {
    pub session_info: Option<SessionInfo>,
    pub subscriptions: Arc<Mutex<HashMap<UInt32, Subscription>>>,
    pub publish_request_queue: Vec<PublishRequest>,
    pub max_publish_requests: usize,
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            session_info: None,
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            publish_request_queue: Vec::with_capacity(MAX_PUBLISH_REQUESTS),
            max_publish_requests: MAX_PUBLISH_REQUESTS,
        }
    }

    pub fn enqueue_publish_request(&mut self, request: PublishRequest) -> Result<(), &'static StatusCode> {
        if self.publish_request_queue.len() >= self.max_publish_requests {
            Err(&BAD_TOO_MANY_PUBLISH_REQUESTS)
        } else {
            self.publish_request_queue.push(request);
            Ok(())
        }
    }

    pub fn expire_stale_publish_requests(&mut self) -> Option<Vec<SupportedMessage>> {
        let now = DateTime::now().as_chrono();
        let mut expired = Vec::with_capacity(self.max_publish_requests);
        for request in self.publish_request_queue.iter() {
            let timestamp: DateTimeUTC = request.request_header.timestamp.as_chrono();
            let timeout_hint = time::Duration::milliseconds(request.request_header.timeout_hint as i64);
            // The request has timed out if the time now exceeds its hint
            if timestamp + timeout_hint < now {
                let now = DateTime::from_chrono(&now);
                let response = PublishResponse {
                    response_header: ResponseHeader::new_notification_response(&now, &BAD_REQUEST_TIMEOUT),
                    subscription_id: 0,
                    available_sequence_numbers: None,
                    more_notifications: false,
                    notification_message: NotificationMessage {
                        sequence_number: 0,
                        publish_time: now.clone(),
                        notification_data: None
                    },
                    results: None,
                    diagnostic_infos: None
                };
                expired.push(SupportedMessage::PublishResponse(response));
            }
        }
        if !expired.is_empty() {
            Some(expired)
        } else {
            None
        }
    }
}
