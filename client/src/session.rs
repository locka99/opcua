//! Session functionality for the current open client connection. This module contains functions
//! to call for all typically synchronous operations during an OPC UA session.
//!
//! The session also has async functionality but that is reserved for publish requests on subscriptions
//! and events.
use std::{
    cmp, thread,
    result::Result,
    collections::HashSet,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
    time::{Instant, Duration},
};
use futures::{
    future,
    Future,
    sync::mpsc::UnboundedSender,
    stream::Stream,
};
use tokio;
use tokio_timer::Interval;

use opcua_core::{
    comms::secure_channel::{Role, SecureChannel},
    crypto::{self, CertificateStore, PrivateKey, SecurityPolicy, X509},
};

use opcua_types::{
    *,
    node_ids::{ObjectId, MethodId},
    service_types::*,
    status_code::StatusCode,
};

use crate::{
    callbacks::{OnDataChange, OnConnectionStatusChange, OnSessionClosed},
    client,
    comms::tcp_transport::TcpTransport,
    message_queue::MessageQueue,
    session_retry::{SessionRetryPolicy, Answer},
    session_state::{SessionState, ConnectionState},
    subscription::{self, Subscription},
    subscription_state::SubscriptionState,
    subscription_timer::{SubscriptionTimer, SubscriptionTimerCommand},
};

/// Information about the server endpoint, security policy, security mode and user identity that the session will
/// will use to establish a connection.
#[derive(Debug)]
pub struct SessionInfo {
    /// The endpoint
    pub endpoint: EndpointDescription,
    /// User identity token
    pub user_identity_token: client::IdentityToken,
    /// Preferred language locales
    pub preferred_locales: Vec<String>,
    /// Client certificate
    pub client_certificate: Option<X509>,
    /// Client private key
    pub client_pkey: Option<PrivateKey>,
}

impl Into<SessionInfo> for EndpointDescription {
    fn into(self) -> SessionInfo {
        (self, client::IdentityToken::Anonymous).into()
    }
}

impl Into<SessionInfo> for (EndpointDescription, client::IdentityToken) {
    fn into(self) -> SessionInfo {
        SessionInfo {
            endpoint: self.0,
            user_identity_token: self.1,
            preferred_locales: Vec::new(),
            client_pkey: None,
            client_certificate: None,
        }
    }
}

/// A session of the client. The session is associated with an endpoint and maintains a state
/// when it is active. The `Session` struct provides functions for all the supported
/// request types in the API.
///
/// Note that not all servers may support all client side requests and calling an unsupported API
/// may cause the connection to be dropped. Your client is expected to know the capabilities of
/// the server it is calling to avoid this.
///
pub struct Session {
    /// The client application's name
    application_description: ApplicationDescription,
    /// The session connection info
    session_info: SessionInfo,
    /// Runtime state of the session, reset if disconnected
    session_state: Arc<RwLock<SessionState>>,
    /// Subscriptions state
    subscription_state: Arc<RwLock<SubscriptionState>>,
    /// Subscription timer command
    timer_command_queue: UnboundedSender<SubscriptionTimerCommand>,
    /// Transport layer
    transport: TcpTransport,
    /// Certificate store
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// Secure channel information
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Message queue
    message_queue: Arc<RwLock<MessageQueue>>,
    /// Connection status callback (TODO move to session state)
    connection_status_callback: Option<Box<dyn OnConnectionStatusChange + Send + Sync + 'static>>,
    /// Session retry policy
    session_retry_policy: SessionRetryPolicy,
}

impl Drop for Session {
    fn drop(&mut self) {
        info!("Session has dropped");
        if self.is_connected() {
            self.disconnect();
        }
    }
}

impl Session {
    /// Create a new session from the supplied application description, certificate store and session
    /// information.
    ///
    /// # Arguments
    ///
    /// * `application_description` - information about the client that will be provided to the server
    /// * `certificate_store` - certificate management on disk
    /// * `session_info` - information required to establish a new session.
    ///
    pub(crate) fn new(application_description: ApplicationDescription, certificate_store: Arc<RwLock<CertificateStore>>, session_info: SessionInfo, session_retry_policy: SessionRetryPolicy) -> Session {
        // TODO take these from the client config
        let decoding_limits = DecodingLimits::default();

        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(certificate_store.clone(), Role::Client, decoding_limits)));
        let message_queue = Arc::new(RwLock::new(MessageQueue::new()));
        let session_state = Arc::new(RwLock::new(SessionState::new(secure_channel.clone(), message_queue.clone())));
        let transport = TcpTransport::new(secure_channel.clone(), session_state.clone(), message_queue.clone());
        let subscription_state = Arc::new(RwLock::new(SubscriptionState::new()));
        let timer_command_queue = SubscriptionTimer::make_timer_command_queue(session_state.clone(), subscription_state.clone());
        Session {
            application_description,
            session_info,
            session_state,
            certificate_store,
            subscription_state,
            timer_command_queue,
            transport,
            secure_channel,
            message_queue,
            connection_status_callback: None,
            session_retry_policy,
        }
    }

    /// Connects to the server, creates and activates a session. If there
    /// is a failure, it will be communicated by the status code in the result.
    pub fn connect_and_activate(&mut self) -> Result<(), StatusCode> {
        // Connect now using the session state
        self.connect()?;
        self.create_session()?;
        self.activate_session()?;
        Ok(())
    }

    /// Sets the session retry policy
    pub fn set_session_retry_policy(&mut self, session_retry_policy: SessionRetryPolicy) {
        self.session_retry_policy = session_retry_policy;
    }

    /// Register a callback to be notified when the session has been closed.
    pub fn set_session_closed_callback<CB>(&mut self, session_closed_callback: CB) where CB: OnSessionClosed + Send + Sync + 'static {
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.set_session_closed_callback(session_closed_callback);
    }

    /// Registers a callback to be notified when the session connection status has changed.
    /// This will be called if connection status changes from connected to disconnected or vice versa.
    pub fn set_connection_status_callback<CB>(&mut self, callback: CB) where CB: OnConnectionStatusChange + Send + Sync + 'static {
        self.connection_status_callback = Some(Box::new(callback));
    }

    /// Reconnects to the server and tries to activate the existing session. If there
    /// is a failure, it will be communicated by the status code in the result.
    pub fn reconnect_and_activate(&mut self) -> Result<(), StatusCode> {
        // Do nothing if already connected / activated
        if self.is_connected() {
            error!("Reconnect is going to do nothing because already connected");
            Err(StatusCode::BadUnexpectedError)
        } else {
            // Clear the existing secure channel state
            {
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                secure_channel.clear_security_token();
            }

            // Cancel any subscription timers
            {
                let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                subscription_state.cancel_subscription_timers();
            }

            // Connect to server (again)
            self.connect_no_retry()?;

            // Attempt to reactivate the existing session
            match self.activate_session() {
                Err(status_code) => {
                    // Activation didn't work, so create a new session
                    info!("Session activation failed on reconnect, error = {}, so creating a new session", status_code);
                    {
                        let mut session_state = trace_write_lock_unwrap!(self.session_state);
                        session_state.reset();
                    }

                    debug!("create_session");
                    self.create_session()?;
                    debug!("activate_session");
                    self.activate_session()?;
                    debug!("reconnect should be complete");
                }
                Ok(_) => {
                    info!("Activation succeeded");
                }
            }
            debug!("transfer_subscriptions_from_old_session");
            self.transfer_subscriptions_from_old_session()?;
            Ok(())
        }
    }

    /// This code attempts to take the existing subscriptions created by a previous session and
    /// either transfer them to this session, or construct them from scratch.
    fn transfer_subscriptions_from_old_session(&mut self) -> Result<(), StatusCode> {
        let subscription_state = self.subscription_state.clone();

        let subscription_ids = {
            let subscription_state = trace_read_lock_unwrap!(subscription_state);
            subscription_state.subscription_ids()
        };

        // Start by getting the subscription ids
        if let Some(subscription_ids) = subscription_ids {
            // Try to use TransferSubscriptions to move subscriptions_ids over. If this
            // works then there is nothing else to do.
            let mut subscription_ids_to_recreate = subscription_ids.iter().map(|s| *s).collect::<HashSet<u32>>();
            if let Ok(transfer_results) = self.transfer_subscriptions(&subscription_ids, true) {
                debug!("transfer_results = {:?}", transfer_results);
                transfer_results.iter().enumerate().for_each(|(i, r)| {
                    if r.status_code.is_good() {
                        // Subscription was transferred so it does not need to be recreated
                        subscription_ids_to_recreate.remove(&subscription_ids[i]);
                    }
                });
            }

            // But if it didn't work, then some or all subscriptions have to be remade.
            if !subscription_ids_to_recreate.is_empty() {
                warn!("Some or all of the existing subscriptions could not be transferred and must be created manually");
            }

            // Now create any subscriptions that could not be transferred
            subscription_ids_to_recreate.iter().for_each(|subscription_id| {
                info!("Recreating subscription {}", subscription_id);
                // Remove the subscription data, create it again from scratch
                let deleted_subscription = {
                    let mut subscription_state = trace_write_lock_unwrap!(subscription_state);
                    subscription_state.delete_subscription(*subscription_id)
                };

                if let Some(subscription) = deleted_subscription {
                    // Attempt to replicate the subscription (subscription id will be new)
                    if let Ok(subscription_id) = self.create_subscription_inner(
                        subscription.publishing_interval(),
                        subscription.lifetime_count(),
                        subscription.max_keep_alive_count(),
                        subscription.max_notifications_per_publish(),
                        subscription.priority(),
                        subscription.publishing_enabled(),
                        subscription.data_change_callback()) {
                        info!("New subscription created with id {}", subscription_id);

                        // For each monitored item
                        let items_to_create = subscription.monitored_items().iter().map(|(_, item)| {
                            MonitoredItemCreateRequest {
                                item_to_monitor: item.item_to_monitor(),
                                monitoring_mode: item.monitoring_mode(),
                                requested_parameters: MonitoringParameters {
                                    client_handle: item.client_handle(),
                                    sampling_interval: item.sampling_interval(),
                                    filter: ExtensionObject::null(),
                                    queue_size: item.queue_size(),
                                    discard_oldest: true,
                                },
                            }
                        }).collect::<Vec<MonitoredItemCreateRequest>>();
                        let _ = self.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create);

                        // Recreate any triggers for the monitored item
                        subscription.monitored_items().iter().for_each(|(_, item)| {
                            let triggered_items = item.triggered_items();
                            if !triggered_items.is_empty() {
                                let links_to_add = triggered_items.iter().map(|i| *i).collect::<Vec<u32>>();
                                self.set_triggering(subscription_id, item.id(), &links_to_add[..], &[]);
                            }
                        });
                    } else {
                        warn!("Could not create a subscription from the existing subscription {}", subscription_id);
                    }
                } else {
                    panic!("Subscription {}, doesn't exist although it should");
                }
            });

            // Now all the subscriptions should have been recreated, it should be possible
            // to kick off the publish timers.
            let subscription_ids = {
                let subscription_state = trace_read_lock_unwrap!(subscription_state);
                subscription_state.subscription_ids().unwrap()
            };
            for subscription_id in &subscription_ids {
                let _ = self.timer_command_queue.unbounded_send(SubscriptionTimerCommand::CreateTimer(*subscription_id));
            }
        }
        Ok(())
    }

    /// Connects to the server using the retry policy to repeat connecting until such time as it
    /// succeeds or the policy says to give up. If there is a failure, it will be
    /// communicated by the status code in the result.
    pub fn connect(&mut self) -> Result<(), StatusCode> {
        loop {
            match self.connect_no_retry() {
                Ok(_) => {
                    info!("Connect was successful");
                    self.session_retry_policy.reset_retry_count();
                    return Ok(());
                }
                Err(status_code) => {
                    self.session_retry_policy.increment_retry_count();
                    warn!("Connect was unsuccessful, error = {}, retries = {}", status_code, self.session_retry_policy.retry_count());

                    use chrono::Utc;
                    match self.session_retry_policy.should_retry_connect(Utc::now()) {
                        Answer::GiveUp => {
                            error!("Session has given up trying to connect to the server after {} retries", self.session_retry_policy.retry_count());
                            return Err(StatusCode::BadNotConnected);
                        }
                        Answer::Retry => {
                            info!("Retrying to connect to server...");
                            self.session_retry_policy.set_last_attempt(Utc::now());
                        }
                        Answer::WaitFor(sleep_for) => {
                            // Sleep for the instructed interval before looping around and trying
                            // once more.
                            thread::sleep(Duration::from_millis(sleep_for as u64));
                        }
                    }
                }
            }
        }
    }

    /// Connects to the server (if possible) using the configured session arguments. If there
    /// is a failure, it will be communicated by the status code in the result.
    pub fn connect_no_retry(&mut self) -> Result<(), StatusCode> {
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();
        info!("Connect");
        let security_policy = SecurityPolicy::from_str(self.session_info.endpoint.security_policy_uri.as_ref()).unwrap();
        if security_policy == SecurityPolicy::Unknown {
            error!("connect, security policy \"{}\" is unknown", self.session_info.endpoint.security_policy_uri.as_ref());
            Err(StatusCode::BadSecurityPolicyRejected)
        } else {
            {
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                secure_channel.set_security_policy(security_policy);
                secure_channel.set_security_mode(self.session_info.endpoint.security_mode);
                let _ = secure_channel.set_remote_cert_from_byte_string(&self.session_info.endpoint.server_certificate);
                info!("Security policy = {:?}", security_policy);
                info!("Security mode = {:?}", self.session_info.endpoint.security_mode);
            }
            self.transport.connect(endpoint_url.as_ref())?;
            self.open_secure_channel()?;

            if let Some(ref mut connection_status) = self.connection_status_callback {
                connection_status.connection_status_change(true);
            }
            Ok(())
        }
    }

    /// Disconnect from the server. Disconnect is an explicit command to drop the socket and throw
    /// away all state information. If you disconnect you cannot reconnect to your existing session
    /// or retrieve any existing subscriptions.
    pub fn disconnect(&mut self) {
        let _ = self.delete_all_subscriptions();
        let _ = self.close_secure_channel();
        self.transport.wait_for_disconnect();
        if let Some(ref mut connection_status) = self.connection_status_callback {
            connection_status.connection_status_change(false);
        }
    }

    /// Test if the session is in a connected state
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    /// Runs a polling loop for this session to perform periodic activity such as processing subscriptions,
    /// as well as recovering from connection errors. The run command will break if the session is disconnected
    /// and cannot be reestablished.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - returns `true` if an action was performed, `false` if no action was performed
    ///                but polling slept for a little bit.
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    pub fn run(session: Arc<RwLock<Session>>) {
        const POLL_SLEEP_INTERVAL: u64 = 50;
        loop {
            // Main thread has nothing to do - just wait for publish events to roll in
            let mut session = session.write().unwrap();
            if let Err(_) = session.poll(POLL_SLEEP_INTERVAL) {
                // Break the loop if connection goes down
                info!("Connection to server broke, so terminating");
                break;
            }
        }
    }

    /// Polls on the session which basically dispatches any pending
    /// async responses, attempts to reconnect if the client is disconnected from the client and
    /// sleeps a little bit if nothing needed to be done.
    ///
    /// Returns `true` if it did something, `false` if it caused the thread to sleep for a bit.
    pub fn poll(&mut self, sleep_for: u64) -> Result<bool, ()> {
        let did_something = if self.is_connected() {
            self.handle_publish_responses()
        } else {
            use chrono::Utc;
            match self.session_retry_policy.should_retry_connect(Utc::now()) {
                Answer::GiveUp => {
                    error!("Session has given up trying to reconnect to the server after {} retries", self.session_retry_policy.retry_count());
                    return Err(());
                }
                Answer::Retry => {
                    info!("Retrying to reconnect to server...");
                    self.session_retry_policy.set_last_attempt(Utc::now());
                    if let Ok(_) = self.reconnect_and_activate() {
                        info!("Retry to connect was successful");
                        self.session_retry_policy.reset_retry_count();
                    } else {
                        self.session_retry_policy.increment_retry_count();
                        warn!("Reconnect was unsuccessful, retries = {}", self.session_retry_policy.retry_count());
                    }
                    true
                }
                Answer::WaitFor(_) => {
                    // Note we could sleep for the interval in the WaitFor(), but the poll() sleeps
                    // anyway so it probably makes no odds.
                    false
                }
            }
        };
        if !did_something {
            // Sleep for a bit, save CPU
            thread::sleep(Duration::from_millis(sleep_for))
        }
        Ok(did_something)
    }

    /// Sends an [`OpenSecureChannelRequest`] to the server
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`OpenSecureChannelRequest`]: ./struct.OpenSecureChannelRequest.html
    ///
    pub fn open_secure_channel(&mut self) -> Result<(), StatusCode> {
        debug!("open_secure_channel");
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.issue_or_renew_secure_channel(SecurityTokenRequestType::Issue)
    }

    /// Sends a [`CloseSecureChannelRequest`] to the server which will cause the server to drop
    /// the connection.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`CloseSecureChannelRequest`]: ./struct.CloseSecureChannelRequest.html
    ///
    pub fn close_secure_channel(&mut self) -> Result<(), StatusCode> {
        let request = CloseSecureChannelRequest {
            request_header: self.make_request_header(),
        };
        // We do not wait for a response because there may not be one. Just return
        let _ = self.async_send_request(request, false);
        Ok(())
    }

    /// Sends a [`CreateSessionRequest`] to the server, returning the session id of the created
    /// session. Internally, the session will store the authentication token which is used for requests
    /// subsequent to this call.
    ///
    /// # Returns
    ///
    /// * `Ok(NodeId)` - Success, session id
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`CreateSessionRequest`]: ./struct.CreateSessionRequest.html
    ///
    pub fn create_session(&mut self) -> Result<NodeId, StatusCode> {
        // Get some state stuff
        let endpoint_url = UAString::from(self.session_info.endpoint.endpoint_url.clone());

        let client_nonce = {
            let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
            secure_channel.local_nonce_as_byte_string()
        };

        let server_uri = UAString::null();
        let session_name = UAString::from("Rust OPCUA Client");

        // Security
        let client_certificate = if let Some(ref client_certificate) = self.session_info.client_certificate {
            client_certificate.as_byte_string()
        } else {
            ByteString::null()
        };

        // Requested session timeout should be larger than your expected subscription rate.
        let requested_session_timeout = self.session_retry_policy.session_timeout();

        let request = CreateSessionRequest {
            request_header: self.make_request_header(),
            client_description: self.application_description.clone(),
            server_uri,
            endpoint_url,
            session_name,
            client_nonce,
            client_certificate,
            requested_session_timeout,
            max_response_message_size: 0,
        };

        debug!("CreateSessionRequest = {:?}", request);

        let response = self.send_request(request)?;
        if let SupportedMessage::CreateSessionResponse(response) = response {
            crate::process_service_result(&response.response_header)?;

            let session_id = {
                let mut session_state = trace_write_lock_unwrap!(self.session_state);
                session_state.set_session_id(response.session_id.clone());
                session_state.set_authentication_token(response.authentication_token.clone());
                {
                    let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                    let _ = secure_channel.set_remote_nonce_from_byte_string(&response.server_nonce);
                    let _ = secure_channel.set_remote_cert_from_byte_string(&response.server_certificate);
                }
                session_state.session_id()
            };

            // debug!("Server nonce is {:?}", response.server_nonce);

            // The server certificate is validated if the policy requires it
            let security_policy = self.security_policy();
            let cert_status_code = if security_policy != SecurityPolicy::None {
                if let Ok(server_certificate) = crypto::X509::from_byte_string(&response.server_certificate) {
                    // Validate server certificate against hostname and application_uri
                    let hostname = hostname_from_url(self.session_info.endpoint.endpoint_url.as_ref()).map_err(|_| StatusCode::BadUnexpectedError)?;
                    let application_uri = self.session_info.endpoint.server.application_uri.as_ref();

                    let certificate_store = trace_write_lock_unwrap!(self.certificate_store);
                    let result = certificate_store.validate_or_reject_application_instance_cert(&server_certificate, Some(&hostname), Some(application_uri));
                    if result.is_bad() {
                        result
                    } else {
                        StatusCode::Good
                    }
                } else {
                    error!("Server did not supply a valid X509 certificate");
                    StatusCode::BadCertificateInvalid
                }
            } else {
                StatusCode::Good
            };

            if !cert_status_code.is_good() {
                error!("Server's certificate was rejected");
                Err(cert_status_code)
            } else {
                // Spawn a task to ping the server to keep the connection alive before the session
                // timeout period.
                debug!("Revised session timeout is {}", response.revised_session_timeout);
                self.spawn_session_activity_task(response.revised_session_timeout);

                // TODO Verify signature using server's public key (from endpoint) comparing with data made from client certificate and nonce.
                // crypto::verify_signature_data(verification_key, security_policy, server_certificate, client_certificate, client_nonce);
                Ok(session_id)
            }
        } else {
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Start a task that will periodically "ping" the server to keep the session alive. The ping rate
    /// will be 3/4 the session timeout rate.
    ///
    /// NOTE: This code assumes that the session_timeout period never changes, e.g. if you
    /// connected to a server, negotiate a timeout period and then for whatever reason need to
    /// reconnect to that same server, you will receive the same timeout. If you get a different
    /// timeout then this code will not care and will continue to ping at the original rate.
    fn spawn_session_activity_task(&mut self, session_timeout: f64) {
        debug!("spawn_session_activity_task({})", session_timeout);

        let connection_state = {
            let session_state = trace_read_lock_unwrap!(self.session_state);
            session_state.connection_state()
        };

        let session_state = self.session_state.clone();
        let connection_state_take_while = connection_state.clone();
        let connection_state_for_each = connection_state.clone();

        // Session activity will happen every 3/4 of the timeout period
        const MIN_SESSION_ACTIVITY_MS: u64 = 1000;
        let session_activity = cmp::max((session_timeout as u64 * 3) / 4, MIN_SESSION_ACTIVITY_MS);
        debug!("session timeout is {}, activity timer is {}", session_timeout, session_activity);

        let last_timeout = Arc::new(Mutex::new(Instant::now()));

        // The timer runs at a higher frequency take_while() to terminate as soon after the session
        // state has terminated. Each time it runs it will test if the interval has elapsed or not.

        let session_activity_interval = Duration::from_millis(session_activity);
        let task = Interval::new(Instant::now(), Duration::from_millis(MIN_SESSION_ACTIVITY_MS))
            .take_while(move |_| {
                let connection_state = trace_read_lock_unwrap!(connection_state_take_while);
                let terminated = match *connection_state {
                    ConnectionState::Finished(_) => true,
                    _ => false
                };
                future::ok(!terminated)
            })
            .for_each(move |_| {
                // Get the time now
                let now = Instant::now();
                let mut last_timeout = last_timeout.lock().unwrap();

                // Calculate to interval since last check
                let interval = now - *last_timeout;
                if interval > session_activity_interval {
                    let connection_state = {
                        let connection_state = trace_read_lock_unwrap!(connection_state_for_each);
                        *connection_state
                    };
                    match connection_state {
                        ConnectionState::Processing => {
                            info!("Session activity keep-alive request");
                            let mut session_state = trace_write_lock_unwrap!(session_state);
                            let request_header = session_state.make_request_header();
                            let request = ReadRequest {
                                request_header,
                                max_age: 1f64,
                                timestamps_to_return: TimestampsToReturn::Server,
                                nodes_to_read: Some(vec![]),
                            };
                            let _ = session_state.async_send_request(request, true);
                        }
                        connection_state => {
                            info!("Session activity keep-alive is doing nothing - connection state = {:?}", connection_state);
                        }
                    };
                    *last_timeout = now;
                }
                Ok(())
            })
            .map(|_| {
                info!("Session activity timer task is finished");
            })
            .map_err(|err| {
                error!("Session activity timer task error = {:?}", err);
            });

        let _ = thread::spawn(move || {
            let _ = tokio::run(task);
        });
    }

    fn security_policy(&self) -> SecurityPolicy {
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        secure_channel.security_policy()
    }

    /// Sends an [`ActivateSessionRequest`] to the server to activate this session
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`ActivateSessionRequest`]: ./struct.ActivateSessionRequest.html
    ///
    pub fn activate_session(&mut self) -> Result<(), StatusCode> {
        let user_identity_token = self.user_identity_token()?;
        let locale_ids = if self.session_info.preferred_locales.is_empty() {
            None
        } else {
            // Ids are
            let locale_ids = self.session_info.preferred_locales.iter().map(|id| UAString::from(id.as_ref())).collect();
            Some(locale_ids)
        };

        let security_policy = self.security_policy();
        let client_signature = match security_policy {
            SecurityPolicy::None => SignatureData::null(),
            _ => {
                let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
                let server_nonce = secure_channel.remote_nonce_as_byte_string();
                let server_cert = secure_channel.remote_cert_as_byte_string();
                // Create a signature data
                // let session_state = self.session_state.lock().unwrap();
                if self.session_info.client_pkey.is_none() {
                    error!("Cannot create client signature - no pkey!");
                    return Err(StatusCode::BadUnexpectedError);
                } else if server_cert.is_null() {
                    error!("Cannot sign server certificate because server cert is null");
                    return Err(StatusCode::BadUnexpectedError);
                } else if server_nonce.is_null() {
                    error!("Cannot sign server certificate because server nonce is null");
                    return Err(StatusCode::BadUnexpectedError);
                }
                let signing_key = self.session_info.client_pkey.as_ref().unwrap();
                crypto::create_signature_data(signing_key, security_policy, &server_cert, &server_nonce)?
            }
        };

        let client_software_certificates = None;
        let user_token_signature = SignatureData::null();

        let request = ActivateSessionRequest {
            request_header: self.make_request_header(),
            client_signature,
            client_software_certificates,
            locale_ids,
            user_identity_token,
            user_token_signature,
        };

        // trace!("ActivateSessionRequest = {:#?}", request);

        let response = self.send_request(request)?;
        if let SupportedMessage::ActivateSessionResponse(response) = response {
            // trace!("ActivateSessionResponse = {:#?}", response);
            crate::process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Sends a [`CancelRequest`] to the server to cancel an outstanding service request.
    ///
    /// # Arguments
    ///
    /// * `request_handle` - Handle to the outstanding request to be cancelled.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - Success, number of cancelled requests
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`CancelRequest`]: ./struct.CancelRequest.html
    ///
    pub fn cancel(&mut self, request_handle: IntegerId) -> Result<u32, StatusCode> {
        let request = CancelRequest {
            request_header: self.make_request_header(),
            request_handle,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::CancelResponse(response) = response {
            crate::process_service_result(&response.response_header)?;
            Ok(response.cancel_count)
        } else {
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Sends a [`FindServersRequest`] to the server denoted by the discovery url
    ///
    /// # Arguments
    ///
    /// * `endpoint_url` - The network address that the Client used to access the Discovery Endpoint.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ApplicationDescription>)` - Success, list of Servers that meet criteria specified in the request.
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`FindServersRequest`]: ./struct.FindServersRequest.html
    ///
    pub fn find_servers<T>(&mut self, endpoint_url: T) -> Result<Vec<ApplicationDescription>, StatusCode> where T: Into<UAString> {
        let request = FindServersRequest {
            request_header: self.make_request_header(),
            endpoint_url: endpoint_url.into(),
            locale_ids: None,
            server_uris: None,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::FindServersResponse(response) = response {
            crate::process_service_result(&response.response_header)?;
            let servers = if let Some(servers) = response.servers {
                servers
            } else {
                Vec::new()
            };
            Ok(servers)
        } else {
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Sends a [`RegisterServerRequest`] to the discovery server to register a server. Although
    /// this function appears in the client API, it is for the benefit of servers that wish to
    /// register with a discovery server. Servers are expected to re-register themselves periodically
    /// with the discovery server, with a maximum of 10 minute intervals.
    ///
    /// # Arguments
    ///
    /// * `server` - The server to register
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`RegisterServerRequest`]: ./struct.FindServersRequest.html
    ///
    pub fn register_server(&mut self, server: RegisteredServer) -> Result<(), StatusCode> {
        let request = RegisterServerRequest {
            request_header: self.make_request_header(),
            server,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::RegisterServerResponse(response) = response {
            crate::process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Returns the subscription state object
    pub fn subscription_state(&self) -> Arc<RwLock<SubscriptionState>> {
        self.subscription_state.clone()
    }

    /// Sends a GetEndpoints request to the server
    pub fn get_endpoints(&mut self) -> Result<Vec<EndpointDescription>, StatusCode> {
        debug!("get_endpoints");
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();
        let request = GetEndpointsRequest {
            request_header: self.make_request_header(),
            endpoint_url,
            locale_ids: None,
            profile_uris: None,
        };

        let response = self.send_request(request)?;
        if let SupportedMessage::GetEndpointsResponse(response) = response {
            crate::process_service_result(&response.response_header)?;
            if response.endpoints.is_none() {
                debug!("get_endpoints, success but no endpoints");
                Ok(Vec::new())
            } else {
                debug!("get_endpoints, success");
                Ok(response.endpoints.unwrap())
            }
        } else {
            error!("get_endpoints failed {:?}", response);
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Sends a BrowseRequest to the server
    pub fn browse(&mut self, nodes_to_browse: &[BrowseDescription]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if nodes_to_browse.is_empty() {
            error!("browse, was not supplied with any nodes to browse");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = BrowseRequest {
                request_header: self.make_request_header(),
                view: ViewDescription {
                    view_id: NodeId::null(),
                    timestamp: DateTime::now(),
                    view_version: 0,
                },
                requested_max_references_per_node: 1000,
                nodes_to_browse: Some(nodes_to_browse.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::BrowseResponse(response) = response {
                debug!("browse, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                error!("browse failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Sends a BrowseNextRequest to the server
    pub fn browse_next(&mut self, release_continuation_points: bool, continuation_points: &[ByteString]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if continuation_points.is_empty() {
            error!("browse_next, was not supplied with any continuation points");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = BrowseNextRequest {
                request_header: self.make_request_header(),
                continuation_points: Some(continuation_points.to_vec()),
                release_continuation_points,
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::BrowseNextResponse(response) = response {
                debug!("browse_next, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                error!("browse_next failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Sends a ReadRequest to the server
    pub fn read(&mut self, nodes_to_read: &[ReadValueId]) -> Result<Option<Vec<DataValue>>, StatusCode> {
        if nodes_to_read.is_empty() {
            // No subscriptions
            error!("read_nodes, was not supplied with any nodes to read");
            Err(StatusCode::BadNothingToDo)
        } else {
            debug!("read_nodes requested to read nodes {:?}", nodes_to_read);
            let request = ReadRequest {
                request_header: self.make_request_header(),
                max_age: 1f64,
                timestamps_to_return: TimestampsToReturn::Server,
                nodes_to_read: Some(nodes_to_read.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::ReadResponse(response) = response {
                debug!("read_nodes, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                error!("write_value failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Sends a WriteRequest to the server
    pub fn write_value(&mut self, nodes_to_write: &[WriteValue]) -> Result<Option<Vec<StatusCode>>, StatusCode> {
        if nodes_to_write.is_empty() {
            // No subscriptions
            error!("write_value() was not supplied with any nodes to write");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = WriteRequest {
                request_header: self.make_request_header(),
                nodes_to_write: Some(nodes_to_write.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::WriteResponse(response) = response {
                debug!("write_value, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                error!("write_value failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Create a subscription by sending a [`CreateSubscriptionRequest`] to the server.
    ///
    /// # Arguments
    ///
    /// * `publishing_interval` - The requested publishing interval defines the cyclic rate that
    ///   the Subscription is being requested to return Notifications to the Client. This interval
    ///   is expressed in milliseconds. This interval is represented by the publishing timer in the
    ///   Subscription state table. The negotiated value for this parameter returned in the
    ///   response is used as the default sampling interval for MonitoredItems assigned to this
    ///   Subscription. If the requested value is 0 or negative, the server shall revise with the
    ///   fastest supported publishing interval in milliseconds.
    /// * `lifetime_count` - Requested lifetime count. The lifetime count shall be a minimum of
    ///   three times the keep keep-alive count. When the publishing timer has expired this
    ///   number of times without a Publish request being available to send a NotificationMessage,
    ///   then the Subscription shall be deleted by the Server.
    /// * `max_keep_alive_count` - Requested maximum keep-alive count. When the publishing timer has
    ///   expired this number of times without requiring any NotificationMessage to be sent, the
    ///   Subscription sends a keep-alive Message to the Client. The negotiated value for this
    ///   parameter is returned in the response. If the requested value is 0, the server shall
    ///   revise with the smallest supported keep-alive count.
    /// * `max_notifications_per_publish` - The maximum number of notifications that the Client
    ///   wishes to receive in a single Publish response. A value of zero indicates that there is
    ///   no limit. The number of notifications per Publish is the sum of monitoredItems in
    ///   the DataChangeNotification and events in the EventNotificationList.
    /// * `priority` - Indicates the relative priority of the Subscription. When more than one
    ///   Subscription needs to send Notifications, the Server should de-queue a Publish request
    ///   to the Subscription with the highest priority number. For Subscriptions with equal
    ///   priority the Server should de-queue Publish requests in a round-robin fashion.
    ///   A Client that does not require special priority settings should set this value to zero.
    /// * `publishing_enabled` - A boolean parameter with the following values - `true` publishing
    ///   is enabled for the Subscription, `false`, publishing is disabled for the Subscription.
    ///   The value of this parameter does not affect the value of the monitoring mode Attribute of
    ///   MonitoredItems.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - identifier for new subscription
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`CreateSubscriptionRequest`]: ./struct.CreateSubscriptionRequest.html
    ///
    pub fn create_subscription<CB>(&mut self, publishing_interval: f64, lifetime_count: u32, max_keep_alive_count: u32, max_notifications_per_publish: u32, priority: u8, publishing_enabled: bool, callback: CB)
                                   -> Result<u32, StatusCode>
        where CB: OnDataChange + Send + Sync + 'static {
        self.create_subscription_inner(publishing_interval, lifetime_count, max_keep_alive_count, max_notifications_per_publish, priority, publishing_enabled, Arc::new(Mutex::new(callback)))
    }

    /// This is the internal handler for create subscription that receives the callback wrapped up and reference counted.
    fn create_subscription_inner(&mut self, publishing_interval: f64, lifetime_count: u32, max_keep_alive_count: u32, max_notifications_per_publish: u32, priority: u8, publishing_enabled: bool,
                                 callback: Arc<Mutex<dyn OnDataChange + Send + Sync + 'static>>)
                                 -> Result<u32, StatusCode>
    {
        let request = CreateSubscriptionRequest {
            request_header: self.make_request_header(),
            requested_publishing_interval: publishing_interval,
            requested_lifetime_count: lifetime_count,
            requested_max_keep_alive_count: max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::CreateSubscriptionResponse(response) = response {
            crate::process_service_result(&response.response_header)?;
            let subscription = Subscription::new(response.subscription_id, response.revised_publishing_interval,
                                                 response.revised_lifetime_count,
                                                 response.revised_max_keep_alive_count,
                                                 max_notifications_per_publish,
                                                 publishing_enabled,
                                                 priority,
                                                 callback);

            {
                let subscription_id = {
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    let subscription_id = subscription.subscription_id();
                    subscription_state.add_subscription(subscription);
                    subscription_id
                };
                let _ = self.timer_command_queue.unbounded_send(SubscriptionTimerCommand::CreateTimer(subscription_id));
            }
            debug!("create_subscription, created a subscription with id {}", response.subscription_id);
            Ok(response.subscription_id)
        } else {
            error!("create_subscription failed {:?}", response);
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Modifies a subscription by sending a [`ModifySubscriptionRequest`] to the server.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - subscription identifier returned from `create_subscription`.
    ///
    /// See `create_subscription` for description of other parameters
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`ModifySubscriptionRequest`]: ./struct.ModifySubscriptionRequest.html
    ///
    pub fn modify_subscription(&mut self, subscription_id: u32, publishing_interval: f64, lifetime_count: u32, max_keep_alive_count: u32, max_notifications_per_publish: u32, priority: u8) -> Result<(), StatusCode> {
        if subscription_id == 0 {
            error!("modify_subscription, subscription id must be non-zero, or the subscription is considered invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("modify_subscription, subscription id does not exist");
            Err(StatusCode::BadInvalidArgument)
        } else {
            let request = ModifySubscriptionRequest {
                request_header: self.make_request_header(),
                subscription_id,
                requested_publishing_interval: publishing_interval,
                requested_lifetime_count: lifetime_count,
                requested_max_keep_alive_count: max_keep_alive_count,
                max_notifications_per_publish,
                priority,
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::ModifySubscriptionResponse(response) = response {
                crate::process_service_result(&response.response_header)?;
                let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                subscription_state.modify_subscription(subscription_id,
                                                       response.revised_publishing_interval,
                                                       response.revised_lifetime_count,
                                                       response.revised_max_keep_alive_count,
                                                       max_notifications_per_publish,
                                                       priority);
                debug!("modify_subscription success for {}", subscription_id);
                Ok(())
            } else {
                error!("modify_subscription failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Deletes a subscription by sending a [`DeleteSubscriptionsRequest`] to the server.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - subscription identifier returned from `create_subscription`.
    ///
    /// # Returns
    ///
    /// * `Ok(StatusCode)` - Service return code for the delete action, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`DeleteSubscriptionsRequest`]: ./struct.DeleteSubscriptionsRequest.html
    ///
    pub fn delete_subscription(&mut self, subscription_id: u32) -> Result<StatusCode, StatusCode> {
        if subscription_id == 0 {
            error!("delete_subscription, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("delete_subscription, subscription id {} does not exist", subscription_id);
            Err(StatusCode::BadInvalidArgument)
        } else {
            let result = self.delete_subscriptions(&[subscription_id][..])?;
            Ok(result[0])
        }
    }

    /// Deletes subscriptions by sending a [`DeleteSubscriptionsRequest`] to the server with the list
    /// of subscriptions to delete.
    ///
    /// # Arguments
    ///
    /// * `subscription_ids` - List of subscription identifiers to delete.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - List of result for delete action on each id, `Good` or `BadSubscriptionIdInvalid`
    ///   The size and order of the list matches the size and order of the input.
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`DeleteSubscriptionsRequest`]: ./struct.DeleteSubscriptionsRequest.html
    ///
    pub fn delete_subscriptions(&mut self, subscription_ids: &[u32]) -> Result<Vec<StatusCode>, StatusCode> {
        if subscription_ids.is_empty() {
            // No subscriptions
            trace!("delete_subscriptions with no subscriptions");
            Err(StatusCode::BadNothingToDo)
        } else {
            // Send a delete request holding all the subscription ides that we wish to delete
            let request = DeleteSubscriptionsRequest {
                request_header: self.make_request_header(),
                subscription_ids: Some(subscription_ids.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::DeleteSubscriptionsResponse(response) = response {
                crate::process_service_result(&response.response_header)?;
                {
                    // Clear out deleted subscriptions, assuming the delete worked
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_ids.iter().for_each(|id| {
                        let _ = subscription_state.delete_subscription(*id);
                    });
                }
                debug!("delete_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                error!("delete_subscriptions failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Deletes all subscriptions by sending a [`DeleteSubscriptionsRequest`] to the server with
    /// ids for all subscriptions.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<(u32, StatusCode)>)` - List of (id, status code) result for delete action on each id, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`DeleteSubscriptionsRequest`]: ./struct.DeleteSubscriptionsRequest.html
    ///
    pub fn delete_all_subscriptions(&mut self) -> Result<Vec<(u32, StatusCode)>, StatusCode> {
        let subscription_ids = {
            let subscription_state = trace_read_lock_unwrap!(self.subscription_state);
            subscription_state.subscription_ids()
        };
        if let Some(ref subscription_ids) = subscription_ids {
            let status_codes = self.delete_subscriptions(&subscription_ids[..])?;
            // Return a list of (id, status_code) for each subscription
            Ok(subscription_ids.iter().zip(status_codes).map(|(id, status_code)| (*id, status_code)).collect())
        } else {
            // No subscriptions
            trace!("delete_all_subscriptions, called when there are no subscriptions");
            Err(StatusCode::BadNothingToDo)
        }
    }

    /// Transfers Subscriptions and their MonitoredItems from one Session to another. For example,
    /// a Client may need to reopen a Session and then transfer its Subscriptions to that Session.
    /// It may also be used by one Client to take over a Subscription from another Client by
    /// transferring the Subscription to its Session.
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `send_initial_values` - A boolean parameter with the following values - `true` the first
    ///   publish response shall contain the current values of all monitored items in the subscription,
    ///   `false`, the first publish response shall contain only the value changes since the last
    ///   publish response was sent.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<TransferResult>)` - Service return code for each transfer subscription.
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`TransferSubscriptionsRequest`]: ./struct.TransferSubscriptionsRequest.html
    ///
    pub fn transfer_subscriptions(&mut self, subscription_ids: &[u32], send_initial_values: bool) -> Result<Vec<TransferResult>, StatusCode> {
        if subscription_ids.is_empty() {
            // No subscriptions
            error!("set_publishing_mode, no subscription ids were provided");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = TransferSubscriptionsRequest {
                request_header: self.make_request_header(),
                subscription_ids: Some(subscription_ids.to_vec()),
                send_initial_values,
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::TransferSubscriptionsResponse(response) = response {
                crate::process_service_result(&response.response_header)?;
                debug!("transfer_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                error!("transfer_subscriptions failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Changes the publishing mode of subscriptiongs by sending a [`SetPublishingModeRequest`] to the server.
    ///
    /// # Arguments
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `publishing_enabled` - A boolean parameter with the following values - `true` publishing
    ///   is enabled for the Subscriptions, `false`, publishing is disabled for the Subscriptions.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - Service return code for the  action for each id, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`SetPublishingModeRequest`]: ./struct.SetPublishingModeRequest.html
    ///
    pub fn set_publishing_mode(&mut self, subscription_ids: &[u32], publishing_enabled: bool) -> Result<Vec<StatusCode>, StatusCode> {
        debug!("set_publishing_mode, for subscriptions {:?}, publishing enabled {}", subscription_ids, publishing_enabled);
        if subscription_ids.is_empty() {
            // No subscriptions
            error!("set_publishing_mode, no subscription ids were provided");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = SetPublishingModeRequest {
                request_header: self.make_request_header(),
                publishing_enabled,
                subscription_ids: Some(subscription_ids.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::SetPublishingModeResponse(response) = response {
                crate::process_service_result(&response.response_header)?;
                {
                    // Clear out all subscriptions, assuming the delete worked
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.set_publishing_mode(subscription_ids, publishing_enabled);
                }
                debug!("set_publishing_mode success");
                Ok(response.results.unwrap())
            } else {
                error!("set_publishing_mode failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Creates monitored items on a subscription by sending a [`CreateMonitoredItemsRequest`] to the server.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_create` - A list of MonitoredItems to be created and assigned to the specified Subscription.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemCreateResult>)` - List of results for the MonitoredItems to create.
    ///    The size and order of the list matches the size and order of the `items_to_create` request parameter.
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`CreateMonitoredItemsRequest`]: ./struct.CreateMonitoredItemsRequest.html
    ///
    pub fn create_monitored_items(&mut self, subscription_id: u32, timestamps_to_return: TimestampsToReturn, items_to_create: &[MonitoredItemCreateRequest]) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        debug!("create_monitored_items, for subscription {}, {} items", subscription_id, items_to_create.len());
        if subscription_id == 0 {
            error!("create_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("create_monitored_items, subscription id {} does not exist", subscription_id);
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_create.is_empty() {
            error!("create_monitored_items, called with no items to create");
            Err(StatusCode::BadNothingToDo)
        } else {
            // Assign each item a unique client handle
            let mut items_to_create = items_to_create.to_vec();
            {
                let mut session_state = trace_write_lock_unwrap!(self.session_state);
                items_to_create.iter_mut().for_each(|i| {
                    i.requested_parameters.client_handle = session_state.next_monitored_item_handle();
                });
            }

            let request = CreateMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                timestamps_to_return,
                items_to_create: Some(items_to_create.clone()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::CreateMonitoredItemsResponse(response) = response {
                crate::process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    debug!("create_monitored_items, {} items created", items_to_create.len());
                    // Set the items in our internal state
                    let items_to_create = items_to_create.iter()
                        .zip(results)
                        .map(|(i, r)| {
                            subscription::CreateMonitoredItem {
                                id: r.monitored_item_id,
                                client_handle: i.requested_parameters.client_handle,
                                discard_oldest: i.requested_parameters.discard_oldest,
                                item_to_monitor: i.item_to_monitor.clone(),
                                monitoring_mode: i.monitoring_mode,
                                queue_size: r.revised_queue_size,
                                sampling_interval: r.revised_sampling_interval,
                            }
                        })
                        .collect::<Vec<subscription::CreateMonitoredItem>>();
                    {
                        let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                        subscription_state.insert_monitored_items(subscription_id, &items_to_create);
                    }
                } else {
                    debug!("create_monitored_items, success but no monitored items were created");
                }
                Ok(response.results.unwrap())
            } else {
                error!("create_monitored_items failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Modifies monitored items on a subscription by sending a [`ModifyMonitoredItemsRequest`] to the server.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_modify` - The list of MonitoredItems to modify.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemModifyResult>)` - List of results for the MonitoredItems to modify.
    ///    The size and order of the list matches the size and order of the `items_to_modify` request parameter.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`ModifyMonitoredItemsRequest`]: ./struct.ModifyMonitoredItemsRequest.html
    ///
    pub fn modify_monitored_items(&mut self, subscription_id: u32, timestamps_to_return: TimestampsToReturn, items_to_modify: &[MonitoredItemModifyRequest]) -> Result<Vec<MonitoredItemModifyResult>, StatusCode> {
        debug!("modify_monitored_items, for subscription {}, {} items", subscription_id, items_to_modify.len());
        if subscription_id == 0 {
            error!("modify_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("modify_monitored_items, subscription id {} does not exist", subscription_id);
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_modify.is_empty() {
            error!("modify_monitored_items, called with no items to modify");
            Err(StatusCode::BadNothingToDo)
        } else {
            let monitored_item_ids = items_to_modify.iter()
                .map(|i| i.monitored_item_id)
                .collect::<Vec<u32>>();
            let request = ModifyMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                timestamps_to_return,
                items_to_modify: Some(items_to_modify.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::ModifyMonitoredItemsResponse(response) = response {
                crate::process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    // Set the items in our internal state
                    let items_to_modify = monitored_item_ids.iter()
                        .zip(results.iter())
                        .map(|(id, r)| {
                            subscription::ModifyMonitoredItem {
                                id: *id,
                                queue_size: r.revised_queue_size,
                                sampling_interval: r.revised_sampling_interval,
                            }
                        })
                        .collect::<Vec<subscription::ModifyMonitoredItem>>();
                    {
                        let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                        subscription_state.modify_monitored_items(subscription_id, &items_to_modify);
                    }
                }
                debug!("modify_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                error!("modify_monitored_items failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Deletes monitored items from a subscription by sending a [`DeleteMonitoredItemsRequest`] to the server.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `items_to_delete` - List of Server-assigned ids for the MonitoredItems to be deleted..
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - List of StatusCodes for the MonitoredItems to delete. The size and
    ///   order of the list matches the size and order of the `items_to_delete` request parameter.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`DeleteMonitoredItemsRequest`]: ./struct.DeleteMonitoredItemsRequest.html
    ///
    pub fn delete_monitored_items(&mut self, subscription_id: u32, items_to_delete: &[u32]) -> Result<Vec<StatusCode>, StatusCode> {
        debug!("delete_monitored_items, subscription {} for {} items", subscription_id, items_to_delete.len());
        if subscription_id == 0 {
            error!("delete_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("delete_monitored_items, subscription id {} does not exist", subscription_id);
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_delete.is_empty() {
            error!("delete_monitored_items, called with no items to delete");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = DeleteMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                monitored_item_ids: Some(items_to_delete.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::DeleteMonitoredItemsResponse(response) = response {
                crate::process_service_result(&response.response_header)?;
                if let Some(_) = response.results {
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.delete_monitored_items(subscription_id, items_to_delete);
                }
                debug!("delete_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                error!("delete_monitored_items failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Sets a monitored item so it becomes the trigger that causes other monitored items to send
    /// change events in the same update. Note that `items_to_remove` is applied before `items_to_add`.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored item to be used as the trigger.
    /// * `monitored_item_id` - the monitored item identifier
    /// * `links_to_add` - zero or more items to be added to the monitored item's trigger list
    /// * `items_to_remove` - zero or more items to be removed from the monitored item's trigger list
    ///
    /// # Returns
    ///
    /// * `Ok(StatusCode)` - Result for the SetTriggering call.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`SetTriggeringRequest`]: ./struct.SetTriggeringRequest.html
    ///
    pub fn set_triggering(&mut self, subscription_id: u32, triggering_item_id: u32, links_to_add: &[u32], links_to_remove: &[u32]) -> Result<StatusCode, StatusCode> {
        if links_to_add.is_empty() && links_to_remove.is_empty() {
            error!("set_triggering, called with nothing to add or remove");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = {
                let links_to_add = if links_to_add.is_empty() { None } else { Some(links_to_add.to_vec()) };
                let links_to_remove = if links_to_remove.is_empty() { None } else { Some(links_to_remove.to_vec()) };
                SetTriggeringRequest {
                    request_header: self.make_request_header(),
                    subscription_id,
                    triggering_item_id,
                    links_to_add,
                    links_to_remove,
                }
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::SetTriggeringResponse(response) = response {
                // TODO we could look through every single add / remove and pick the worst result here

                // Update client side state
                let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                subscription_state.set_triggering(subscription_id, triggering_item_id, links_to_add, links_to_remove);

                Ok(StatusCode::Good)
            } else {
                error!("set_triggering failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }


    /// Calls a single method on an object on the server by sending a [`CallRequest`] to the server.
    ///
    /// # Arguments
    ///
    /// * `method` - The method to call. Note this function takes anything that can be turned into
    ///   a [`CallMethodRequest`] which includes a (`NodeId`, `NodeId`, `Option<Vec<Variant>>`)
    ///   which refers to the object id, method id, and input arguments respectively.
    /// * `items_to_delete` - List of Server-assigned ids for the MonitoredItems to be deleted..
    ///
    /// # Returns
    ///
    /// * `Ok(CallMethodResult)` - Result for the Method call.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`CallRequest`]: ./struct.CallRequest.html
    /// [`CallMethodRequest`]: ./struct.CallMethodRequest.html
    ///
    pub fn call_method<T>(&mut self, method: T) -> Result<CallMethodResult, StatusCode> where T: Into<CallMethodRequest> {
        debug!("call_method");
        let methods_to_call = Some(vec![method.into()]);
        let request = CallRequest {
            request_header: self.make_request_header(),
            methods_to_call,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::CallResponse(response) = response {
            if let Some(mut results) = response.results {
                if results.len() != 1 {
                    error!("call_method, expecting a result from the call to the server, got {} results", results.len());
                    Err(StatusCode::BadUnexpectedError)
                } else {
                    Ok(results.remove(0))
                }
            } else {
                error!("call_method, expecting a result from the call to the server, got nothing");
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Calls GetMonitoredItems via call_method(), putting a sane interface on the input / output.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - Server allocated identifier for the subscription to return monitored items for.
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<u32>, Vec<u32>))` - Result for call, consisting a list of (monitored_item_id, client_handle)
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    pub fn call_get_monitored_items(&mut self, subscription_id: u32) -> Result<(Vec<u32>, Vec<u32>), StatusCode> {
        let args = Some(vec![Variant::from(subscription_id)]);
        let object_id: NodeId = ObjectId::Server.into();
        let method_id: NodeId = MethodId::Server_GetMonitoredItems.into();
        let request: CallMethodRequest = (object_id, method_id, args).into();
        let response = self.call_method(request)?;
        if let Some(mut result) = response.output_arguments {
            if result.len() == 2 {
                let server_handles = result.remove(0).as_u32_array().map_err(|_| StatusCode::BadUnexpectedError)?;
                let client_handles = result.remove(0).as_u32_array().map_err(|_| StatusCode::BadUnexpectedError)?;
                Ok((server_handles, client_handles))
            } else {
                error!("Expected a result with 2 args and didn't get it.");
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            error!("Expected a result and didn't get it.");
            Err(StatusCode::BadUnexpectedError)
        }
    }

    // Test if the subscription by id exists
    fn subscription_exists(&self, subscription_id: u32) -> bool {
        let subscription_state = trace_read_lock_unwrap!(self.subscription_state);
        subscription_state.subscription_exists(subscription_id)
    }

    /// Synchronously sends a request. The return value is the response to the request
    fn send_request<T>(&mut self, request: T) -> Result<SupportedMessage, StatusCode> where T: Into<SupportedMessage> {
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.send_request(request)
    }

    /// Asynchronously sends a request. The return value is the request handle of the request
    fn async_send_request<T>(&mut self, request: T, is_async: bool) -> Result<u32, StatusCode> where T: Into<SupportedMessage> {
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.async_send_request(request, is_async)
    }

    fn user_identity_token(&self) -> Result<ExtensionObject, StatusCode> {
        let user_token_type = match self.session_info.user_identity_token {
            client::IdentityToken::Anonymous => {
                UserTokenType::Anonymous
            }
            client::IdentityToken::UserName(_, _) => {
                UserTokenType::Username
            }
        };

        let endpoint = &self.session_info.endpoint;
        let policy_id = endpoint.find_policy_id(user_token_type);

        // Return the result
        if policy_id.is_none() {
            error!("Cannot find user token type {:?} for this endpoint, cannot connect", user_token_type);
            Err(StatusCode::BadSecurityPolicyRejected)
        } else {
            match self.session_info.user_identity_token {
                client::IdentityToken::Anonymous => {
                    let token = AnonymousIdentityToken {
                        policy_id: policy_id.unwrap(),
                    };
                    Ok(ExtensionObject::from_encodable(ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary, &token))
                }
                client::IdentityToken::UserName(ref user, ref pass) => {
                    // TODO Check that the security policy is something we can supply
                    let token = UserNameIdentityToken {
                        policy_id: policy_id.unwrap(),
                        user_name: UAString::from(user.as_ref()),
                        password: ByteString::from(pass.as_bytes()),
                        encryption_algorithm: UAString::null(),
                    };
                    Ok(ExtensionObject::from_encodable(ObjectId::UserNameIdentityToken_Encoding_DefaultBinary, &token))
                }
            }
        }
    }

    /// Construct a request header for the session. All requests after create session are expected
    /// to supply an authentication token.
    fn make_request_header(&mut self) -> RequestHeader {
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.make_request_header()
    }

    // Process any async messages we expect to receive
    fn handle_publish_responses(&mut self) -> bool {
        let responses = {
            let mut message_queue = trace_write_lock_unwrap!(self.message_queue);
            message_queue.async_responses()
        };
        if responses.is_empty() {
            false
        } else {
            debug!("Processing {} async messages", responses.len());
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
        debug!("handle_publish_response");
        let mut wait_for_publish_response = false;
        match response {
            SupportedMessage::PublishResponse(response) => {
                debug!("PublishResponse");

                // Update subscriptions based on response
                // Queue acknowledgements for next request
                let notification_message = response.notification_message.clone();
                let subscription_id = response.subscription_id;

                // Queue an acknowledgement for this request
                {
                    let mut session_state = trace_write_lock_unwrap!(self.session_state);
                    session_state.add_subscription_acknowledgement(SubscriptionAcknowledgement {
                        subscription_id,
                        sequence_number: notification_message.sequence_number,
                    });
                }

                let decoding_limits = {
                    let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
                    secure_channel.decoding_limits()
                };

                // Process data change notifications
                let data_change_notifications = notification_message.data_change_notifications(&decoding_limits);
                if !data_change_notifications.is_empty() {
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.subscription_data_change(subscription_id, &data_change_notifications);
                }
            }
            SupportedMessage::ServiceFault(response) => {
                let service_result = response.response_header.service_result;
                debug!("Service fault received with {} error code", service_result);
                trace!("ServiceFault {:?}", response);
                // Terminate timer if
                if service_result == StatusCode::BadTooManyPublishRequests {
                    // Turn off publish requests until server says otherwise
                    wait_for_publish_response = false;
                }
            }
            _ => {
                info!("Unhandled response")
            }
        }

        // Turn on/off publish requests
        {
            let mut session_state = trace_write_lock_unwrap!(self.session_state);
            session_state.set_wait_for_publish_response(wait_for_publish_response);
        }
    }
}
