use std::u32;
use std::collections::{HashSet, HashMap, VecDeque};

use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use opcua_types::{UInt32, NodeId, UAString, DateTime, ExtensionObject};
use opcua_types::SupportedMessage;
use opcua_types::service_types::{RequestHeader, SubscriptionAcknowledgement};

const DEFAULT_REQUEST_TIMEOUT: u32 = 10 * 1000;
const SEND_BUFFER_SIZE: usize = 65536;
const RECEIVE_BUFFER_SIZE: usize = 65536;
const MAX_BUFFER_SIZE: usize = 65536;


/// A simple handle factory for incrementing sequences of numbers.
struct Handle {
    next: UInt32,
    first: UInt32,
}

impl Handle {
    /// Creates a new handle factory, that starts with the supplied number
    pub fn new(first: UInt32) -> Handle {
        Handle {
            next: first,
            first,
        }
    }

    /// Returns the next handle to be issued, internally incrementing each time so the handle
    /// is always different until it wraps back to the start.
    pub fn next(&mut self) -> UInt32 {
        let next = self.next;
        // Increment next
        if self.next == u32::MAX {
            self.next = self.first;
        } else {
            self.next += 1;
        }
        next
    }
}

/// Session's state indicates connection status, negotiated times and sizes,
/// and security tokens.
pub struct SessionState {
    /// The request timeout is how long the session will wait from sending a request expecting a response
    /// if no response is received the rclient will terminate.
    request_timeout: u32,
    /// Size of the send buffer
    send_buffer_size: usize,
    /// Size of the
    receive_buffer_size: usize,
    /// Maximum message size
    max_message_size: usize,
    /// The session's id - used for diagnostic info
    session_id: NodeId,
    /// The sesion authentication token, used for session activation
    authentication_token: NodeId,
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
    /// Abort flag
    abort: bool,
    ///
    sender: Option<UnboundedSender<SupportedMessage>>,
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
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
            abort: false,
            sender: None
        }
    }

    // Creates the transmission queue that outgoing requests will be sent over
    pub fn make_request_channel(&mut self) -> UnboundedReceiver<SupportedMessage> {
        let (tx, rx) = mpsc::unbounded::<SupportedMessage>();
        self.sender = Some(tx);
        rx
    }

    pub fn set_session_id(&mut self, session_id: NodeId) {
        self.session_id = session_id
    }

    pub fn session_id(&self) -> NodeId {
        self.session_id.clone()
    }

    pub fn receive_buffer_size(&self) -> usize {
        self.receive_buffer_size
    }

    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    pub fn request_timeout(&self) -> u32 {
        self.request_timeout
    }

    pub fn send_buffer_size(&self) -> usize {
        self.send_buffer_size
    }

    pub fn subscription_acknowledgements(&mut self) -> Vec<SubscriptionAcknowledgement> {
        self.subscription_acknowledgements.drain(..).collect()
    }

    pub fn abort(&mut self) {
        self.abort = true;
    }

    pub fn is_abort(&self) -> bool {
        self.abort
    }

    pub fn authentication_token(&self) -> &NodeId {
        &self.authentication_token
    }

    pub fn set_authentication_token(&mut self, authentication_token: NodeId) {
        self.authentication_token = authentication_token;
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

    /// Returns the next monitored item handle
    pub fn next_monitored_item_handle(&mut self) -> UInt32 {
        self.monitored_item_handle.next()
    }

    /// Called by the session to add a request to be sent
    pub fn add_request(&mut self, request: SupportedMessage, async: bool) {
        self.inflight_requests.insert((request.request_handle(), async));
        let _ = self.sender.as_ref().unwrap().unbounded_send(request);
        self.requests.push_front((request, async));
    }

    pub fn request_was_processed(&mut self, request_handle: UInt32) {
        // Don't know if request was async or not, so try removing either.
        let _ = self.inflight_requests.remove(&(request_handle, false));
        let _ = self.inflight_requests.remove(&(request_handle, true));
    }

    /// Called when a session's request times out. This call allows the session state to remove
    /// the request as pending and ignore any response that arrives for it.
    pub fn request_has_timed_out(&mut self, request_handle: UInt32) {
        info!("Request with handle {} has timed out and any response will be ignored", request_handle);
        let value = (request_handle, false);
        let _ = self.inflight_requests.remove(&value);
    }

    /// Called by the connection to store a response for the consumption of the session.
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

    /// Takes all pending asynchronous responses into a vector sorted oldest to latest and
    /// returns them to the caller.
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

    /// Called by the session to take the identified response if one exists, otherwise None
    pub fn take_response(&mut self, request_handle: UInt32) -> Option<SupportedMessage> {
        if let Some(response) = self.responses.remove(&request_handle) {
            Some(response.0)
        } else {
            None
        }
    }
}
