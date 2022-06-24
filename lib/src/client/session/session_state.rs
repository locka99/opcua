// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    u32,
};

use chrono::Duration;
use tokio::time::Instant;

use crate::{
    client::{
        callbacks::{OnConnectionStatusChange, OnSessionClosed},
        message_queue::MessageQueue,
        process_unexpected_response,
        session::{session_debug, session_trace},
        subscription_state::SubscriptionState,
    },
    core::{
        comms::secure_channel::SecureChannel, handle::Handle, supported_message::SupportedMessage,
    },
    crypto::SecurityPolicy,
    sync::*,
    types::{status_code::StatusCode, *},
};

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

#[derive(Clone)]
/// A manager for the connection status with some helpers for common actions.
pub(crate) struct ConnectionStateMgr {
    state: Arc<RwLock<ConnectionState>>,
}

impl ConnectionStateMgr {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ConnectionState::NotStarted)),
        }
    }

    pub fn state(&self) -> ConnectionState {
        let connection_state = trace_read_lock!(self.state);
        *connection_state
    }

    pub fn set_state(&self, state: ConnectionState) {
        trace!("setting connection state to {:?}", state);
        let mut connection_state = trace_write_lock!(self.state);
        *connection_state = state;
    }

    pub fn set_finished(&self, finished_code: StatusCode) {
        self.set_state(ConnectionState::Finished(finished_code));
    }

    pub fn is_connected(&self) -> bool {
        !matches!(
            self.state(),
            ConnectionState::NotStarted
                | ConnectionState::Connecting
                | ConnectionState::Finished(_)
        )
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.state(), ConnectionState::Finished(_))
    }
}

lazy_static! {
    static ref NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);
}

/// Session's state indicates connection status, negotiated times and sizes,
/// and security tokens.
pub(crate) struct SessionState {
    /// A unique identifier for the session, this is NOT the session id assigned after a session is created
    id: u32,
    /// Time offset between the client and the server.
    client_offset: Duration,
    /// Ignore clock skew between the client and the server.
    ignore_clock_skew: bool,
    /// Secure channel information
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Connection state - what the session's connection is currently doing
    connection_state: ConnectionStateMgr,
    /// The request timeout is how long the session will wait from sending a request expecting a response
    /// if no response is received the client will terminate.
    request_timeout: u32,
    /// Size of the send buffer
    send_buffer_size: usize,
    /// Size of the
    receive_buffer_size: usize,
    /// Maximum message size
    max_message_size: usize,
    /// Maximum chunk size
    max_chunk_count: usize,
    /// The session's id assigned after a connection and used for diagnostic info
    session_id: NodeId,
    /// The session authentication token, used for session activation
    authentication_token: NodeId,
    /// The next handle to assign to a request
    request_handle: Handle,
    /// Next monitored item client side handle
    monitored_item_handle: Handle,
    /// Subscription acknowledgements pending for send
    subscription_acknowledgements: Vec<SubscriptionAcknowledgement>,
    /// Subscription state
    subscription_state: Arc<RwLock<SubscriptionState>>,
    /// Connection closed callback
    session_closed_callback: Option<Box<dyn OnSessionClosed + Send + Sync + 'static>>,
    /// Connection status callback
    connection_status_callback: Option<Box<dyn OnConnectionStatusChange + Send + Sync + 'static>>,
    /// Message queue.
    pub(crate) message_queue: Arc<RwLock<MessageQueue>>,
}

impl OnSessionClosed for SessionState {
    fn on_session_closed(&mut self, status_code: StatusCode) {
        debug!("Session was closed with status = {}", status_code);
        if let Some(ref mut session_closed_callback) = self.session_closed_callback {
            session_closed_callback.on_session_closed(status_code);
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
    const SEND_BUFFER_SIZE: usize = 65535;
    const RECEIVE_BUFFER_SIZE: usize = 65535;
    const MAX_BUFFER_SIZE: usize = 65535;

    pub fn new(
        ignore_clock_skew: bool,
        secure_channel: Arc<RwLock<SecureChannel>>,
        subscription_state: Arc<RwLock<SubscriptionState>>,
    ) -> SessionState {
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        SessionState {
            id,
            client_offset: Duration::zero(),
            ignore_clock_skew,
            secure_channel,
            connection_state: ConnectionStateMgr::new(),
            request_timeout: Self::DEFAULT_REQUEST_TIMEOUT,
            send_buffer_size: Self::SEND_BUFFER_SIZE,
            receive_buffer_size: Self::RECEIVE_BUFFER_SIZE,
            max_message_size: Self::MAX_BUFFER_SIZE,
            max_chunk_count: constants::MAX_CHUNK_COUNT,
            request_handle: Handle::new(Self::FIRST_REQUEST_HANDLE),
            session_id: NodeId::null(),
            authentication_token: NodeId::null(),
            monitored_item_handle: Handle::new(Self::FIRST_MONITORED_ITEM_HANDLE),
            subscription_acknowledgements: Vec::new(),
            subscription_state,
            session_closed_callback: None,
            connection_status_callback: None,
            message_queue: Arc::new(RwLock::new(MessageQueue::new())),
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn set_client_offset(&mut self, offset: Duration) {
        self.client_offset = self.client_offset + offset;
        debug!("Client offset set to {}", self.client_offset);
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

    pub fn max_chunk_count(&self) -> usize {
        self.max_chunk_count
    }

    pub fn request_timeout(&self) -> u32 {
        self.request_timeout
    }

    pub fn send_buffer_size(&self) -> usize {
        self.send_buffer_size
    }

    pub fn add_subscription_acknowledgement(
        &mut self,
        subscription_acknowledgement: SubscriptionAcknowledgement,
    ) {
        self.subscription_acknowledgements
            .push(subscription_acknowledgement);
    }

    pub fn set_authentication_token(&mut self, authentication_token: NodeId) {
        self.authentication_token = authentication_token;
    }

    pub fn set_session_closed_callback<CB>(&mut self, session_closed_callback: CB)
    where
        CB: OnSessionClosed + Send + Sync + 'static,
    {
        self.session_closed_callback = Some(Box::new(session_closed_callback));
    }

    pub fn set_connection_status_callback<CB>(&mut self, connection_status_callback: CB)
    where
        CB: OnConnectionStatusChange + Send + Sync + 'static,
    {
        self.connection_status_callback = Some(Box::new(connection_status_callback));
    }

    pub(crate) fn on_connection_status_change(&mut self, connected: bool) {
        if let Some(ref mut connection_status) = self.connection_status_callback {
            connection_status.on_connection_status_change(connected);
        }
    }

    pub(crate) fn connection_state(&self) -> ConnectionStateMgr {
        self.connection_state.clone()
    }

    /// Construct a request header for the session. All requests after create session are expected
    /// to supply an authentication token.
    pub fn make_request_header(&mut self) -> RequestHeader {
        RequestHeader {
            authentication_token: self.authentication_token.clone(),
            timestamp: DateTime::now_with_offset(self.client_offset),
            request_handle: self.request_handle.next(),
            return_diagnostics: DiagnosticBits::empty(),
            timeout_hint: self.request_timeout,
            ..Default::default()
        }
    }

    /// Sends a publish request containing acknowledgements for previous notifications.
    pub fn async_publish(&mut self) -> Result<u32, StatusCode> {
        let subscription_acknowledgements = if self.subscription_acknowledgements.is_empty() {
            None
        } else {
            let subscription_acknowledgements: Vec<SubscriptionAcknowledgement> =
                self.subscription_acknowledgements.drain(..).collect();
            // Debug sequence nrs
            if log_enabled!(log::Level::Debug) {
                let sequence_nrs: Vec<u32> = subscription_acknowledgements
                    .iter()
                    .map(|ack| ack.sequence_number)
                    .collect();
                debug!(
                    "async_publish is acknowledging subscription acknowledgements with sequence nrs {:?}",
                    sequence_nrs
                );
            }
            Some(subscription_acknowledgements)
        };
        let request = PublishRequest {
            request_header: self.make_request_header(),
            subscription_acknowledgements,
        };
        let request_handle = self.async_send_request(request, None)?;

        {
            let mut subscription_state = trace_write_lock!(self.subscription_state);
            subscription_state.set_last_publish_request(Instant::now());
        }

        debug!("async_publish, request sent with handle {}", request_handle);
        Ok(request_handle)
    }

    /// Synchronously sends a request. The return value is the response to the request
    pub(crate) fn send_request<T>(&mut self, request: T) -> Result<SupportedMessage, StatusCode>
    where
        T: Into<SupportedMessage>,
    {
        // A channel is created to receive the response
        let (sender, receiver) = mpsc::sync_channel(1);
        // Send the request
        let request_handle = self.async_send_request(request, Some(sender))?;
        // Wait for the response
        let request_timeout = self.request_timeout();
        self.wait_for_sync_response(request_handle, request_timeout, receiver)
    }

    pub(crate) fn reset(&mut self) {
        // Clear tokens, ids etc.
        self.session_id = NodeId::null();
        self.authentication_token = NodeId::null();
        self.request_handle.reset();
        self.monitored_item_handle.reset();

        // Clear the message queue
        {
            let mut message_queue = trace_write_lock!(self.message_queue);
            message_queue.clear();
        };
    }

    /// Asynchronously sends a request. The return value is the request handle of the request
    pub(crate) fn async_send_request<T>(
        &mut self,
        request: T,
        sender: Option<SyncSender<SupportedMessage>>,
    ) -> Result<u32, StatusCode>
    where
        T: Into<SupportedMessage>,
    {
        let request = request.into();
        match request {
            SupportedMessage::OpenSecureChannelRequest(_)
            | SupportedMessage::CloseSecureChannelRequest(_) => {}
            _ => {
                // Make sure secure channel token hasn't expired
                let _ = self.ensure_secure_channel_token();
            }
        }

        // TODO should error here if not connected

        // Enqueue the request
        let request_handle = request.request_handle();
        self.add_request(request, sender);

        Ok(request_handle)
    }

    pub(crate) fn quit(&self) {
        let message_queue = trace_read_lock!(self.message_queue);
        message_queue.quit();
    }

    /// Wait for a response with a matching request handle. If request handle is 0 then no match
    /// is performed and in fact the function is expected to receive no messages except asynchronous
    /// and housekeeping events from the server. A 0 handle will cause the wait to process at most
    /// one async message before returning.
    fn wait_for_sync_response(
        &mut self,
        request_handle: u32,
        request_timeout: u32,
        receiver: Receiver<SupportedMessage>,
    ) -> Result<SupportedMessage, StatusCode> {
        if request_handle == 0 {
            panic!("Request handle must be non zero");
        }
        // Receive messages until the one expected comes back. Publish responses will be consumed
        // silently.
        let request_timeout = std::time::Duration::from_millis(request_timeout as u64);
        receiver.recv_timeout(request_timeout).map_err(|_| {
            info!("Timeout waiting for response from server");
            self.request_has_timed_out(request_handle);
            StatusCode::BadTimeout
        })
    }

    fn request_has_timed_out(&self, request_handle: u32) {
        let mut message_queue = trace_write_lock!(self.message_queue);
        message_queue.request_has_timed_out(request_handle)
    }

    fn add_request(
        &mut self,
        request: SupportedMessage,
        sender: Option<SyncSender<SupportedMessage>>,
    ) {
        let mut message_queue = trace_write_lock!(self.message_queue);
        message_queue.add_request(request, sender)
    }

    /// Checks if secure channel token needs to be renewed and renews it
    fn ensure_secure_channel_token(&mut self) -> Result<(), StatusCode> {
        let should_renew_security_token = {
            let secure_channel = trace_read_lock!(self.secure_channel);
            secure_channel.should_renew_security_token()
        };
        if should_renew_security_token {
            self.issue_or_renew_secure_channel(SecurityTokenRequestType::Renew)
        } else {
            Ok(())
        }
    }

    pub(crate) fn issue_or_renew_secure_channel(
        &mut self,
        request_type: SecurityTokenRequestType,
    ) -> Result<(), StatusCode> {
        trace!("issue_or_renew_secure_channel({:?})", request_type);

        const REQUESTED_LIFETIME: u32 = 60000; // TODO

        let (security_mode, security_policy, client_nonce) = {
            let mut secure_channel = trace_write_lock!(self.secure_channel);
            let client_nonce = secure_channel.security_policy().random_nonce();
            secure_channel.set_local_nonce(client_nonce.as_ref());
            (
                secure_channel.security_mode(),
                secure_channel.security_policy(),
                client_nonce,
            )
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
            // Extract the security token from the response.
            let mut security_token = response.security_token.clone();

            // When ignoring clock skew, we calculate the time offset between the client and the
            // server and use that offset to compensate for the difference in time when setting
            // the timestamps in the request headers and when decoding timestamps in messages
            // received from the server.
            if self.ignore_clock_skew && !response.response_header.timestamp.is_null() {
                let offset = response.response_header.timestamp - DateTime::now();
                // Make sure to apply the offset to the security token in the current response.
                security_token.created_at = security_token.created_at - offset;
                // Update the client offset by adding the new offset. When the secure channel is
                // renewed its already using the client offset calculated when issuing the secure
                // channel and only needs to be updated to accommodate any additional clock skew.
                self.set_client_offset(offset);
            }

            debug!("Setting transport's security token");
            {
                let mut secure_channel = trace_write_lock!(self.secure_channel);
                secure_channel.set_client_offset(self.client_offset);
                secure_channel.set_security_token(security_token);

                if security_policy != SecurityPolicy::None
                    && (security_mode == MessageSecurityMode::Sign
                        || security_mode == MessageSecurityMode::SignAndEncrypt)
                {
                    secure_channel.set_remote_nonce_from_byte_string(&response.server_nonce)?;
                    secure_channel.derive_keys();
                }
            }
            Ok(())
        } else {
            Err(process_unexpected_response(response))
        }
    }

    // Process any async messages we expect to receive
    pub(crate) fn handle_publish_responses(&mut self) -> bool {
        let responses = {
            let mut message_queue = trace_write_lock!(self.message_queue);
            message_queue.async_responses()
        };
        if responses.is_empty() {
            false
        } else {
            session_debug!(self, "Processing {} async messages", responses.len());
            for response in responses {
                self.handle_async_response(response);
            }
            true
        }
    }

    /// This is the handler for asynchronous responses which are currently assumed to be publish
    /// responses. It maintains the acknowledgements to be sent and sends the data change
    /// notifications to the client for processing.
    fn handle_async_response(&mut self, response: SupportedMessage) {
        session_debug!(self, "handle_async_response");
        match response {
            SupportedMessage::PublishResponse(response) => {
                session_debug!(self, "PublishResponse");

                // Update subscriptions based on response
                // Queue acknowledgements for next request
                let notification_message = response.notification_message.clone();
                let subscription_id = response.subscription_id;

                // Queue an acknowledgement for this request (if it has data)
                if let Some(ref notification_data) = notification_message.notification_data {
                    if !notification_data.is_empty() {
                        self.add_subscription_acknowledgement(SubscriptionAcknowledgement {
                            subscription_id,
                            sequence_number: notification_message.sequence_number,
                        });
                    }
                }

                let decoding_options = {
                    let secure_channel = trace_read_lock!(self.secure_channel);
                    secure_channel.decoding_options()
                };

                // Process data change notifications
                if let Some((data_change_notifications, events)) =
                    notification_message.notifications(&decoding_options)
                {
                    session_debug!(
                        self,
                        "Received notifications, data changes = {}, events = {}",
                        data_change_notifications.len(),
                        events.len()
                    );
                    if !data_change_notifications.is_empty() {
                        let mut subscription_state = trace_write_lock!(self.subscription_state);
                        subscription_state
                            .on_data_change(subscription_id, &data_change_notifications);
                    }
                    if !events.is_empty() {
                        let mut subscription_state = trace_write_lock!(self.subscription_state);
                        subscription_state.on_event(subscription_id, &events);
                    }
                }

                // Send another publish request
                let _ = self.async_publish();
            }
            SupportedMessage::ServiceFault(response) => {
                let service_result = response.response_header.service_result;
                session_debug!(
                    self,
                    "Service fault received with {} error code",
                    service_result
                );
                session_trace!(self, "ServiceFault {:?}", response);

                match service_result {
                    StatusCode::BadTimeout => {
                        debug!("Publish request timed out so sending another");
                        let _ = self.async_publish();
                    }
                    StatusCode::BadTooManyPublishRequests => {
                        // Turn off publish requests until server says otherwise
                        debug!("Server tells us too many publish requests so waiting for a response before resuming");
                    }
                    StatusCode::BadSessionClosed
                    | StatusCode::BadSessionIdInvalid
                    | StatusCode::BadNoSubscription
                    | StatusCode::BadSubscriptionIdInvalid => {
                        self.on_session_closed(service_result)
                    }
                    _ => (),
                }
            }
            _ => {
                info!("{} unhandled response", self.session_id());
            }
        }
    }

    /// Returns the next monitored item handle
    pub fn next_monitored_item_handle(&mut self) -> u32 {
        self.monitored_item_handle.next()
    }
}
