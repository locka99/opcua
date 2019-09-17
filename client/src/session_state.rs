use std::{
    self,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU32, Ordering},
    },
    u32,
};

use chrono;

use opcua_core::{
    comms::secure_channel::SecureChannel,
    crypto::SecurityPolicy,
    handle::Handle,
};
use opcua_types::{
    *,
    status_code::StatusCode,
};

use crate::{callbacks::OnSessionClosed, message_queue::MessageQueue};

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ConnectionState {
    /// No connect has been made yet
    NotStarted,
    /// Connecting
    Connecting,
    /// Connection success
    Connected,
    // Waiting for ACK from the server
    WaitingForAck,
    // Connection is running
    Processing,
    // Connection is finished, possibly after an error
    Finished(StatusCode),
}

lazy_static! {
    static ref NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);
}

/// Session's state indicates connection status, negotiated times and sizes,
/// and security tokens.
pub(crate) struct SessionState {
    /// A unique identifier for the session, this is NOT the session id assigned after a session is created
    id: u32,
    /// Secure channel information
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Connection state - what the session's connection is currently doing
    connection_state: Arc<RwLock<ConnectionState>>,
    /// The request timeout is how long the session will wait from sending a request expecting a response
    /// if no response is received the rclient will terminate.
    request_timeout: u32,
    /// Size of the send buffer
    send_buffer_size: usize,
    /// Size of the
    receive_buffer_size: usize,
    /// Maximum message size
    max_message_size: usize,
    /// The session's id assigned after a connection and used for diagnostic info
    session_id: NodeId,
    /// The sesion authentication token, used for session activation
    authentication_token: NodeId,
    /// The next handle to assign to a request
    request_handle: Handle,
    /// Next monitored item client side handle
    monitored_item_handle: Handle,
    /// Unacknowledged
    subscription_acknowledgements: Vec<SubscriptionAcknowledgement>,
    /// A flag which tells client to wait for a publish response before sending any new publish
    /// requests
    wait_for_publish_response: bool,
    /// The message queue
    message_queue: Arc<RwLock<MessageQueue>>,
    /// Connection closed callback
    session_closed_callback: Option<Box<dyn OnSessionClosed + Send + Sync + 'static>>,
}

impl OnSessionClosed for SessionState {
    fn session_closed(&mut self, status_code: StatusCode) {
        debug!("Session was closed with status = {}", status_code);
        if let Some(ref mut session_closed_callback) = self.session_closed_callback {
            session_closed_callback.session_closed(status_code);
        }
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        info!("SessionState has dropped");
    }
}

impl SessionState {
    const FIRST_REQUEST_HANDLE: u32 = 1;
    const FIRST_MONITORED_ITEM_HANDLE: u32 = 1000;

    const DEFAULT_REQUEST_TIMEOUT: u32 = 10 * 1000;
    const SEND_BUFFER_SIZE: usize = 65536;
    const RECEIVE_BUFFER_SIZE: usize = 65536;
    const MAX_BUFFER_SIZE: usize = 65536;

    /// Used for synchronous polling
    const SYNC_POLLING_PERIOD: u64 = 50;

    pub fn new(secure_channel: Arc<RwLock<SecureChannel>>, message_queue: Arc<RwLock<MessageQueue>>) -> SessionState {
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        SessionState {
            id,
            secure_channel,
            connection_state: Arc::new(RwLock::new(ConnectionState::NotStarted)),
            request_timeout: Self::DEFAULT_REQUEST_TIMEOUT,
            send_buffer_size: Self::SEND_BUFFER_SIZE,
            receive_buffer_size: Self::RECEIVE_BUFFER_SIZE,
            max_message_size: Self::MAX_BUFFER_SIZE,
            request_handle: Handle::new(Self::FIRST_REQUEST_HANDLE),
            session_id: NodeId::null(),
            authentication_token: NodeId::null(),
            monitored_item_handle: Handle::new(Self::FIRST_MONITORED_ITEM_HANDLE),
            message_queue,
            subscription_acknowledgements: Vec::new(),
            wait_for_publish_response: false,
            session_closed_callback: None,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
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

    pub fn add_subscription_acknowledgement(&mut self, subscription_acknowledgement: SubscriptionAcknowledgement) {
        self.subscription_acknowledgements.push(subscription_acknowledgement);
    }

    //pub fn authentication_token(&self) -> &NodeId {
    //    &self.authentication_tokenPOL
    //}

    pub fn set_authentication_token(&mut self, authentication_token: NodeId) {
        self.authentication_token = authentication_token;
    }

    pub fn set_session_closed_callback<CB>(&mut self, session_closed_callback: CB) where CB: OnSessionClosed + Send + Sync + 'static {
        self.session_closed_callback = Some(Box::new(session_closed_callback));
    }

    pub(crate) fn connection_state(&self) -> Arc<RwLock<ConnectionState>> {
        self.connection_state.clone()
    }

    pub fn wait_for_publish_response(&self) -> bool {
        self.wait_for_publish_response
    }

    pub fn set_wait_for_publish_response(&mut self, wait_for_publish_response: bool) {
        if self.wait_for_publish_response && !wait_for_publish_response {
            debug!("Publish requests are enabled again");
        } else if !self.wait_for_publish_response && wait_for_publish_response {
            debug!("Publish requests will be disabled until some publish responses start to arrive");
        }
        self.wait_for_publish_response = wait_for_publish_response;
    }

    /// Construct a request header for the session. All requests after create session are expected
    /// to supply an authentication token.
    pub fn make_request_header(&mut self) -> RequestHeader {
        RequestHeader {
            authentication_token: self.authentication_token.clone(),
            timestamp: DateTime::now(),
            request_handle: self.request_handle.next(),
            return_diagnostics: DiagnosticBits::empty(),
            audit_entry_id: UAString::null(),
            timeout_hint: self.request_timeout,
            additional_header: ExtensionObject::null(),
        }
    }

    /// Sends a publish request containing acknowledgements for previous notifications.
    pub fn async_publish(&mut self, subscription_acknowledgements: &[SubscriptionAcknowledgement]) -> Result<u32, StatusCode> {
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

    pub(crate) fn reset(&mut self) {
        // Clear tokens, ids etc.
        self.session_id = NodeId::null();
        self.authentication_token = NodeId::null();
        self.request_handle.reset();
        self.monitored_item_handle.reset();

        // Clear the message queue
        {
            let mut message_queue = trace_write_lock_unwrap!(self.message_queue);
            message_queue.clear();
        };
    }

    /// Asynchronously sends a request. The return value is the request handle of the request
    pub(crate) fn async_send_request<T>(&mut self, request: T, is_async: bool) -> Result<u32, StatusCode> where T: Into<SupportedMessage> {
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
        self.add_request(request, is_async);

        Ok(request_handle)
    }

    pub(crate) fn quit(&mut self) {
        let mut message_queue = trace_write_lock_unwrap!(self.message_queue);
        message_queue.quit();
    }

    /// Wait for a response with a matching request handle. If request handle is 0 then no match
    /// is performed and in fact the function is expected to receive no messages except asynchronous
    /// and housekeeping events from the server. A 0 handle will cause the wait to process at most
    /// one async message before returning.
    fn wait_for_sync_response(&mut self, request_handle: u32, request_timeout: u32) -> Result<SupportedMessage, StatusCode> {
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
                    return Err(StatusCode::BadTimeout);
                }
                // Sleep before trying again
                std::thread::sleep(std::time::Duration::from_millis(Self::SYNC_POLLING_PERIOD));
            }
        }
    }

    fn take_response(&self, request_handle: u32) -> Option<SupportedMessage> {
        let mut message_queue = trace_write_lock_unwrap!(self.message_queue);
        message_queue.take_response(request_handle)
    }

    fn request_has_timed_out(&self, request_handle: u32) {
        let mut message_queue = trace_write_lock_unwrap!(self.message_queue);
        message_queue.request_has_timed_out(request_handle)
    }

    fn add_request(&mut self, request: SupportedMessage, is_async: bool) {
        let mut message_queue = trace_write_lock_unwrap!(self.message_queue);
        message_queue.add_request(request, is_async)
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

        const REQUESTED_LIFETIME: u32 = 60000; // TODO

        let (security_mode, security_policy, client_nonce) = {
            let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
            let client_nonce = secure_channel.security_policy().random_nonce();
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
        let response = self.send_request(request)?;
        if let SupportedMessage::OpenSecureChannelResponse(response) = response {
            debug!("Setting transport's security token");
            {
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                secure_channel.set_security_token(response.security_token.clone());

                if security_policy != SecurityPolicy::None && (security_mode == MessageSecurityMode::Sign || security_mode == MessageSecurityMode::SignAndEncrypt) {
                    secure_channel.set_remote_nonce_from_byte_string(&response.server_nonce)?;
                    secure_channel.derive_keys();
                }
            }
            Ok(())
        } else {
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Returns the next monitored item handle
    pub fn next_monitored_item_handle(&mut self) -> u32 {
        self.monitored_item_handle.next()
    }
}
