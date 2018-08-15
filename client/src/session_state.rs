use std::u32;
use std::collections::{HashSet, HashMap, VecDeque};

use opcua_types::{UInt32, NodeId, UAString, DateTime, ExtensionObject};
use opcua_types::SupportedMessage;
use opcua_types::service_types::{RequestHeader, SubscriptionAcknowledgement};

const DEFAULT_SESSION_TIMEOUT: u32 = 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT: u32 = 10 * 1000;
const SEND_BUFFER_SIZE: usize = 65536;
const RECEIVE_BUFFER_SIZE: usize = 65536;
const MAX_BUFFER_SIZE: usize = 65536;

struct Handle {
    next: UInt32,
    wraps_on: UInt32,
}

impl Handle {
    pub fn new(first: UInt32) -> Handle {
        Handle {
            next: first,
            wraps_on: u32::MAX,
        }
    }

    pub fn next(&mut self) -> UInt32 {
        if self.next == self.wraps_on {
            self.next = 1;
        } else {
            self.next += 1;
        }
        self.next
    }
}

/// Session's state indicates connection status, negotiated times and sizes,
/// and security tokens.
pub struct SessionState {
    /// The request timeout is how long the session will wait from sending a request expecting a response
    /// if no response is received the rclient will terminate.
    pub request_timeout: u32,
    /// Session timeout in milliseconds
    pub session_timeout: u32,
    /// Size of the send buffer
    pub send_buffer_size: usize,
    /// Size of the
    pub receive_buffer_size: usize,
    /// Maximum message size
    pub max_message_size: usize,
    /// The session's id - used for diagnostic info
    session_id: NodeId,
    /// The sesion authentication token, used for session activation
    pub authentication_token: NodeId,
    /// The next handle to assign to a request
    request_handle: Handle,
    /// Next monitored item client side handle
    monitored_item_handle: Handle,
    /// Unacknowledged
    pub subscription_acknowledgements: Vec<SubscriptionAcknowledgement>,
    /// A flag which tells client to wait for a publish response before sending any new publish
    /// requests
    pub wait_for_publish_response: bool,
    /// Request queue contains messages yet to be sent. Once sent, their request handle will be
    /// placed in the pending request handles.
    requests: VecDeque<(SupportedMessage, bool)>,
    /// The requests that are in-flight, defined by their request handle and an async flag. Basically,
    /// the sent requests reside here  until the response returns at which point the entry is removed.
    /// If a response is received for which there is no entry, the response will be discarded.
    inflight_requests: HashSet<(UInt32, bool)>,
    /// A map of incoming responses waiting to be processed
    responses: HashMap<UInt32, (SupportedMessage, bool)>,

}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            send_buffer_size: SEND_BUFFER_SIZE,
            receive_buffer_size: RECEIVE_BUFFER_SIZE,
            max_message_size: MAX_BUFFER_SIZE,
            request_handle: Handle::new(1),
            session_id: NodeId::null(),
            authentication_token: NodeId::null(),
            monitored_item_handle: Handle::new(1000),
            requests: VecDeque::new(),
            inflight_requests: HashSet::new(),
            responses: HashMap::new(),
            subscription_acknowledgements: Vec::new(),
            wait_for_publish_response: false,
        }
    }

    pub fn set_session_id(&mut self, session_id: NodeId) {
        self.session_id = session_id
    }

    pub fn session_id(&self) -> NodeId {
        self.session_id.clone()
    }

    pub fn subscription_acknowledgements(&mut self) -> Vec<SubscriptionAcknowledgement> {
        self.subscription_acknowledgements.drain(..).collect()
    }

    /// Construct a request header for the session. All requests after create session are expected
    /// to supply an authentication token.
    pub fn make_request_header(&mut self) -> RequestHeader {
        let request_header = RequestHeader {
            authentication_token: self.authentication_token.clone(),
            timestamp: DateTime::now(),
            request_handle: self.request_handle.next(),
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint: self.request_timeout,
            additional_header: ExtensionObject::null(),
        };
        request_header
    }

    pub fn next_monitored_item_handle(&mut self) -> UInt32 {
        self.monitored_item_handle.next()
    }

    pub fn add_request(&mut self, request: SupportedMessage, async: bool) {
        self.requests.push_front((request, async));
    }

    pub fn next_request(&mut self) -> Option<(SupportedMessage, bool)> {
        self.requests.pop_back()
    }

    pub fn add_pending_request(&mut self, request_handle: UInt32, async: bool) {
        let value = (request_handle, async);
        self.inflight_requests.insert(value);
    }

    /// Removes a synchronous request which has timed out
    pub fn remove_pending_request_timeout(&mut self, request_handle: UInt32) {
        info!("Request with handle {} has timed out and any response will be ignored", request_handle);
        let value = (request_handle, false);
        let _ = self.inflight_requests.remove(&value);
    }

    pub fn store_response(&mut self, response: SupportedMessage) {
        // Remove corresponding request handle from inflight queue, add to responses
        let request_handle = response.request_handle();
        // Remove the inflight request
        // This true / false is slightly clunky.
        if let Some(request) = self.inflight_requests.take(&(request_handle, true)) {
            self.responses.insert(request_handle, (response, request.1));
        } else if let Some(request) = self.inflight_requests.take(&(request_handle, false)) {
            self.responses.insert(request_handle, (response, request.1));
        } else {
            error!("A response with request handle {} doesn't belong to any request and will be ignored", request_handle);
        }
    }

    pub fn async_responses(&mut self) -> Vec<SupportedMessage> {
        // Gather up all request handles
        let mut async_handles = self.responses.iter()
            .filter(|(_, v)| v.1)
            .map(|(k, _)| *k)
            .collect::<Vec<_>>();

        // Order them from oldest to latest (except if handles wrap)
        async_handles.sort();

        // Remove each item from the map and return to caller
        async_handles.iter()
            .map(|k| self.responses.remove(k).unwrap().0)
            .collect()
    }

    pub fn remove_response(&mut self, request_handle: UInt32) -> Option<SupportedMessage> {
        if let Some(response) = self.responses.remove(&request_handle) {
            Some(response.0)
        } else {
            None
        }
    }
}
