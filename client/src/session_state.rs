use std;
use std::u32;
use std::collections::{HashSet, HashMap};
use std::sync::{Arc, RwLock};

use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use chrono;

use opcua_core::comms::secure_channel::SecureChannel;
use opcua_core::crypto::SecurityPolicy;

use opcua_types::{UInt32, NodeId, UAString, DateTime, ExtensionObject};
use opcua_types::*;
use opcua_types::service_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;

const DEFAULT_REQUEST_TIMEOUT: u32 = 10 * 1000;
const SEND_BUFFER_SIZE: usize = 65536;
const RECEIVE_BUFFER_SIZE: usize = 65536;
const MAX_BUFFER_SIZE: usize = 65536;

/// Used for synchronous polling
const SYNC_POLLING_PERIOD: u64 = 50;

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
    /// Secure channel information
    secure_channel: Arc<RwLock<SecureChannel>>,
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
    /// The requests that are in-flight, defined by their request handle and an async flag. Basically,
    /// the sent requests reside here  until the response returns at which point the entry is removed.
    /// If a response is received for which there is no entry, the response will be discarded.
    inflight_requests: HashSet<(UInt32, bool)>,
    /// A map of incoming responses waiting to be processed
    responses: HashMap<UInt32, (SupportedMessage, bool)>,
    /// Abort flag
    abort: bool,
    /// This is the queue that messages will be sent onto the transport for sending
    sender: Option<UnboundedSender<SupportedMessage>>,
}

impl SessionState {
    pub fn new(secure_channel: Arc<RwLock<SecureChannel>>) -> SessionState {
        SessionState {
            secure_channel,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            send_buffer_size: SEND_BUFFER_SIZE,
            receive_buffer_size: RECEIVE_BUFFER_SIZE,
            max_message_size: MAX_BUFFER_SIZE,
            request_handle: Handle::new(1),
            session_id: NodeId::null(),
            authentication_token: NodeId::null(),
            monitored_item_handle: Handle::new(1000),
            inflight_requests: HashSet::new(),
            responses: HashMap::new(),
            subscription_acknowledgements: Vec::new(),
            wait_for_publish_response: false,
            abort: false,
            sender: None,
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

    /// Sends a publish request containing acknowledgements for previous notifications.
    /// TODO this function needs to be refactored as an asynchronous operation.
    pub fn async_publish(&mut self, subscription_acknowledgements: &[SubscriptionAcknowledgement]) -> Result<UInt32, StatusCode> {
        debug!("async_publish with {} subscription acknowledgements", subscription_acknowledgements.len());
        let request = PublishRequest {
            request_header: self.make_request_header(),
            subscription_acknowledgements: if subscription_acknowledgements.is_empty() { None } else { Some(subscription_acknowledgements.to_vec()) },
        };
        let request_handle = self.async_send_request(request, true)?;
        debug!("async_publish, request sent with handle {}", request_handle);
        Ok(request_handle)
    }

    /// Synchronously sends a request. The return value is the response to the request
    pub(crate) fn send_request<T>(&mut self, request: T) -> Result<SupportedMessage, StatusCode> where T: Into<SupportedMessage> {
        // Send the request
        let request_handle = self.async_send_request(request, false)?;
        // Wait for the response
        let request_timeout = self.request_timeout();
        self.wait_for_sync_response(request_handle, request_timeout)
    }

    /// Asynchronously sends a request. The return value is the request handle of the request
    pub(crate) fn async_send_request<T>(&mut self, request: T, async: bool) -> Result<UInt32, StatusCode> where T: Into<SupportedMessage> {
        let request = request.into();
        match request {
            SupportedMessage::OpenSecureChannelRequest(_) | SupportedMessage::CloseSecureChannelRequest(_) => {}
            _ => {
                // Make sure secure channel token hasn't expired
                let _ = self.ensure_secure_channel_token();
            }
        }

        // TODO should error here if not connected

        // Enqueue the request
        let request_handle = request.request_handle();
        self.add_request(request, async);

        Ok(request_handle)
    }

    /// Wait for a response with a matching request handle. If request handle is 0 then no match
    /// is performed and in fact the function is expected to receive no messages except asynchronous
    /// and housekeeping events from the server. A 0 handle will cause the wait to process at most
    /// one async message before returning.
    fn wait_for_sync_response(&mut self, request_handle: UInt32, request_timeout: UInt32) -> Result<SupportedMessage, StatusCode> {
        if request_handle == 0 {
            panic!("Request handle must be non zero");
        }

        // Receive messages until the one expected comes back. Publish responses will be consumed
        // silently.
        let start = chrono::Utc::now();
        loop {
            if let Some(response) = self.take_response(request_handle) {
                // Got the response
                return Ok(response);
            } else {
                let now = chrono::Utc::now();
                let request_duration = now.signed_duration_since(start);
                if request_duration.num_milliseconds() >= request_timeout as i64 {
                    info!("Timeout waiting for response from server");
                    self.request_has_timed_out(request_handle);
                    return Err(BadTimeout);
                }
                // Sleep before trying again
                std::thread::sleep(std::time::Duration::from_millis(SYNC_POLLING_PERIOD));
            }
        }
    }

    /// Checks if secure channel token needs to be renewed and renews it
    fn ensure_secure_channel_token(&mut self) -> Result<(), StatusCode> {
        let should_renew_security_token = {
            let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
            secure_channel.should_renew_security_token()
        };
        if should_renew_security_token {
            self.issue_or_renew_secure_channel(SecurityTokenRequestType::Renew)
        } else {
            Ok(())
        }
    }

    pub(crate) fn issue_or_renew_secure_channel(&mut self, request_type: SecurityTokenRequestType) -> Result<(), StatusCode> {
        trace!("issue_or_renew_secure_channel({:?})", request_type);

        const REQUESTED_LIFETIME: UInt32 = 60000; // TODO

        let (security_mode, security_policy, client_nonce) = {
            let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
            let client_nonce = secure_channel.security_policy().nonce();
            secure_channel.set_local_nonce(client_nonce.as_ref());
            (secure_channel.security_mode(), secure_channel.security_policy(), client_nonce)
        };

        info!("Making secure channel request");
        info!("security_mode = {:?}", security_mode);
        info!("security_policy = {:?}", security_policy);

        let requested_lifetime = REQUESTED_LIFETIME;
        let request = OpenSecureChannelRequest {
            request_header: self.make_request_header(),
            client_protocol_version: 0,
            request_type,
            security_mode,
            client_nonce,
            requested_lifetime,
        };
        let response = self.send_request(SupportedMessage::OpenSecureChannelRequest(request))?;
        if let SupportedMessage::OpenSecureChannelResponse(response) = response {
            debug!("Setting transport's security token");
            {
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                secure_channel.set_security_token(response.security_token);

                if security_policy != SecurityPolicy::None && (security_mode == MessageSecurityMode::Sign || security_mode == MessageSecurityMode::SignAndEncrypt) {
                    secure_channel.set_remote_nonce_from_byte_string(&response.server_nonce)?;
                    secure_channel.derive_keys();
                }
            }
            Ok(())
        } else {
            Err(::process_unexpected_response(response))
        }
    }

    /// Returns the next monitored item handle
    pub fn next_monitored_item_handle(&mut self) -> UInt32 {
        self.monitored_item_handle.next()
    }

    /// Called by the session to add a request to be sent
    pub fn add_request(&mut self, request: SupportedMessage, async: bool) {
        let request_handle = request.request_handle();
        debug!("Sending request {:?} to be sent", request);
        self.inflight_requests.insert((request_handle, async));
        let _ = self.sender.as_ref().unwrap().unbounded_send(request);
    }

    pub fn request_was_processed(&mut self, request_handle: UInt32) {
        debug!("Request {} was processed by the server", request_handle);
    }

    /// Called when a session's request times out. This call allows the session state to remove
    /// the request as pending and ignore any response that arrives for it.
    pub fn request_has_timed_out(&mut self, request_handle: UInt32) {
        info!("Request {} has timed out and any response will be ignored", request_handle);
        let _ = self.inflight_requests.remove(&(request_handle, false));
        let _ = self.inflight_requests.remove(&(request_handle, true));
    }

    /// Called by the connection to store a response for the consumption of the session.
    pub fn store_response(&mut self, response: SupportedMessage) {
        // Remove corresponding request handle from inflight queue, add to responses
        let request_handle = response.request_handle();
        debug!("Response to Request {} has been stored", request_handle);
        // Remove the inflight request
        // This true / false is slightly clunky.
        if let Some(request) = self.inflight_requests.take(&(request_handle, true)) {
            self.responses.insert(request_handle, (response, request.1));
        } else if let Some(request) = self.inflight_requests.take(&(request_handle, false)) {
            self.responses.insert(request_handle, (response, request.1));
        } else {
            error!("A response with request handle {} doesn't belong to any request and will be ignored, inflight requests = {:?}", request_handle, self.inflight_requests);
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
