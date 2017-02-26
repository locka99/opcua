use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use opcua_core::types::*;

use subscriptions::*;

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
        let max_publish_requests = 10;
        SessionState {
            session_info: None,
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            publish_request_queue: Vec::with_capacity(max_publish_requests),
            max_publish_requests: max_publish_requests,
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
}
