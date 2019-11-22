//! Session functionality for the current open client connection. This module contains functions
//! to call for all typically synchronous operations during an OPC UA session.
//!
//! The session also has async functionality but that is reserved for publish requests on subscriptions
//! and events.
use std::{
    cmp, thread, convert::TryFrom, result::Result, collections::HashSet, str::FromStr,
    sync::{Arc, Mutex, RwLock, mpsc},
    time::{Instant, Duration},
};
use futures::{
    future, Future,
    sync::mpsc::UnboundedSender,
    stream::Stream,
};
use tokio;
use tokio_timer::Interval;

use opcua_core::{
    comms::secure_channel::{Role, SecureChannel},
    crypto::{self, CertificateStore, SecurityPolicy, X509, user_identity::make_user_name_identity_token},
};

use opcua_types::{
    *,
    node_ids::{ObjectId, MethodId},
    status_code::StatusCode,
};

use crate::{
    callbacks::{OnSubscriptionNotification, OnConnectionStatusChange, OnSessionClosed},
    client,
    comms::tcp_transport::TcpTransport,
    message_queue::MessageQueue,
    session_retry::{SessionRetryPolicy, Answer},
    session_state::{SessionState, ConnectionState},
    subscription::{self, Subscription},
    subscription_state::SubscriptionState,
    subscription_timer::{SubscriptionTimer, SubscriptionTimerCommand},
};

macro_rules! session_warn {
    ($session: expr, $($arg:tt)*) =>  {
        warn!("{} {}", $session.session_id(), format!($($arg)*));
    }
}

macro_rules! session_error {
    ($session: expr, $($arg:tt)*) =>  {
        error!("{} {}", $session.session_id(), format!($($arg)*));
    }
}

macro_rules! session_debug {
    ($session: expr, $($arg:tt)*) =>  {
        debug!("{} {}", $session.session_id(), format!($($arg)*));
    }
}

macro_rules! session_trace {
    ($session: expr, $($arg:tt)*) =>  {
        trace!("{} {}", $session.session_id(), format!($($arg)*));
    }
}

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
        }
    }
}

/// A `Session` runs in a loop, which can be terminated by sending it a `SessionCommand`.
pub enum SessionCommand {
    /// Stop running as soon as possible
    Stop
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
    /// The client application's name.
    application_description: ApplicationDescription,
    /// The session connection info.
    session_info: SessionInfo,
    /// Runtime state of the session, reset if disconnected.
    session_state: Arc<RwLock<SessionState>>,
    /// Subscriptions state.
    subscription_state: Arc<RwLock<SubscriptionState>>,
    /// Subscription timer command.
    timer_command_queue: UnboundedSender<SubscriptionTimerCommand>,
    /// Transport layer.
    transport: TcpTransport,
    /// Certificate store.
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// Secure channel information.
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Message queue.
    message_queue: Arc<RwLock<MessageQueue>>,
    /// Session retry policy.
    session_retry_policy: SessionRetryPolicy,
}

impl Drop for Session {
    fn drop(&mut self) {
        info!("Session has dropped");
        self.disconnect();
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
    /// # Returns
    ///
    /// * `Session` - the interface that shall be used to communicate between the client and the server.
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
            session_retry_policy,
        }
    }

    /// Connects to the server, creates and activates a session. If there
    /// is a failure, it will be communicated by the status code in the result.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - connection has happened and the session is activated
    /// * `Err(StatusCode)` - reason for failure
    ///
    pub fn connect_and_activate(&mut self) -> Result<(), StatusCode> {
        // Connect now using the session state
        self.connect()?;
        self.create_session()?;
        self.activate_session()?;
        Ok(())
    }

    /// Sets the session retry policy that dictates what this session will do if the connection
    /// fails or goes down. The retry policy enables the session to retry a connection on an
    /// interval up to a maxmimum number of times.
    ///
    /// # Arguments
    ///
    /// * `session_retry_policy` - the session retry policy to use
    ///
    pub fn set_session_retry_policy(&mut self, session_retry_policy: SessionRetryPolicy) {
        self.session_retry_policy = session_retry_policy;
    }

    /// Register a callback to be notified when the session has been closed.
    ///
    /// # Arguments
    ///
    /// * `session_closed_callback` - the session closed callback
    ///
    pub fn set_session_closed_callback<CB>(&mut self, session_closed_callback: CB) where CB: OnSessionClosed + Send + Sync + 'static {
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.set_session_closed_callback(session_closed_callback);
    }

    /// Registers a callback to be notified when the session connection status has changed.
    /// This will be called if connection status changes from connected to disconnected or vice versa.
    ///
    /// # Arguments
    ///
    /// * `connection_status_callback` - the connection status callback.
    ///
    pub fn set_connection_status_callback<CB>(&mut self, connection_status_callback: CB) where CB: OnConnectionStatusChange + Send + Sync + 'static {
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.set_connection_status_callback(connection_status_callback);
    }

    /// Reconnects to the server and tries to activate the existing session. If there
    /// is a failure, it will be communicated by the status code in the result. You should not
    /// call this if there is a session retry policy associated with the session.
    ///
    /// Reconnecting will attempt to transfer or recreate subscriptions that were on the old
    /// session before it terminated.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - reconnection has happened and the session is activated
    /// * `Err(StatusCode)` - reason for failure
    ///
    pub fn reconnect_and_activate(&mut self) -> Result<(), StatusCode> {
        // Do nothing if already connected / activated
        if self.is_connected() {
            session_error!(self, "Reconnect is going to do nothing because already connected");
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

                    session_debug!(self, "create_session");
                    self.create_session()?;
                    session_debug!(self, "activate_session");
                    self.activate_session()?;
                    session_debug!(self, "reconnect should be complete");
                }
                Ok(_) => {
                    info!("Activation succeeded");
                }
            }
            session_debug!(self, "transfer_subscriptions_from_old_session");
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
                session_debug!(self, "transfer_results = {:?}", transfer_results);
                transfer_results.iter().enumerate().for_each(|(i, r)| {
                    if r.status_code.is_good() {
                        // Subscription was transferred so it does not need to be recreated
                        subscription_ids_to_recreate.remove(&subscription_ids[i]);
                    }
                });
            }

            // But if it didn't work, then some or all subscriptions have to be remade.
            if !subscription_ids_to_recreate.is_empty() {
                session_warn!(self, "Some or all of the existing subscriptions could not be transferred and must be created manually");
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
                        subscription.notification_callback()) {
                        info!("New subscription created with id {}", subscription_id);

                        // For each monitored item
                        let items_to_create = subscription.monitored_items().iter().map(|(_, item)| {
                            MonitoredItemCreateRequest {
                                item_to_monitor: item.item_to_monitor().clone(),
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

                        // Recreate any triggers for the monitored item. This code assumes monitored item
                        // ids are the same value as they were in the previous subscription.
                        subscription.monitored_items().iter().for_each(|(_, item)| {
                            let triggered_items = item.triggered_items();
                            if !triggered_items.is_empty() {
                                let links_to_add = triggered_items.iter().map(|i| *i).collect::<Vec<u32>>();
                                let _ = self.set_triggering(subscription_id, item.id(), links_to_add.as_slice(), &[]);
                            }
                        });
                    } else {
                        session_warn!(self, "Could not create a subscription from the existing subscription {}", subscription_id);
                    }
                } else {
                    panic!("Subscription {}, doesn't exist although it should", subscription_id);
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
                    session_warn!(self, "Connect was unsuccessful, error = {}, retries = {}", status_code, self.session_retry_policy.retry_count());

                    use chrono::Utc;
                    match self.session_retry_policy.should_retry_connect(Utc::now()) {
                        Answer::GiveUp => {
                            session_error!(self, "Session has given up trying to connect to the server after {} retries", self.session_retry_policy.retry_count());
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

    /// Connects to the server using the configured session arguments. No attempt is made to retry
    /// the connection if the attempt fails. If there is a failure, it will be communicated by the
    /// status code in the result.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - connection has happened
    /// * `Err(StatusCode)` - reason for failure
    ///
    pub fn connect_no_retry(&mut self) -> Result<(), StatusCode> {
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();
        info!("Connect");
        let security_policy = SecurityPolicy::from_str(self.session_info.endpoint.security_policy_uri.as_ref()).unwrap();
        if security_policy == SecurityPolicy::Unknown {
            session_error!(self, "connect, security policy \"{}\" is unknown", self.session_info.endpoint.security_policy_uri.as_ref());
            Err(StatusCode::BadSecurityPolicyRejected)
        } else {
            let (cert, key) = {
                let certificate_store = trace_write_lock_unwrap!(self.certificate_store);
                certificate_store.read_own_cert_and_pkey_optional()
            };

            {
                let mut secure_channel = trace_write_lock_unwrap!(self.secure_channel);
                secure_channel.set_private_key(key);
                secure_channel.set_cert(cert);
                secure_channel.set_security_policy(security_policy);
                secure_channel.set_security_mode(self.session_info.endpoint.security_mode);
                let _ = secure_channel.set_remote_cert_from_byte_string(&self.session_info.endpoint.server_certificate);
                info!("Security policy = {:?}", security_policy);
                info!("Security mode = {:?}", self.session_info.endpoint.security_mode);
            }
            self.transport.connect(endpoint_url.as_ref())?;
            self.open_secure_channel()?;
            self.on_connection_status_change(true);
            Ok(())
        }
    }

    pub(crate) fn session_state(&self) -> Arc<RwLock<SessionState>> {
        self.session_state.clone()
    }

    /// Disconnect from the server. Disconnect is an explicit command to drop the socket and throw
    /// away all state information. If you disconnect you cannot reconnect to your existing session
    /// or retrieve any existing subscriptions.
    pub fn disconnect(&mut self) {
        if self.is_connected() {
            let _ = self.delete_all_subscriptions();
            let _ = self.close_secure_channel();

            {
                let mut session_state = trace_write_lock_unwrap!(self.session_state);
                session_state.quit();
            }

            self.transport.wait_for_disconnect();
            self.on_connection_status_change(false);
        }
    }

    /// Test if the session is in a connected state
    ///
    /// # Returns
    ///
    /// * `true` - Session is connected
    /// * `false` - Session is not connected
    ///
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    /// Internal constant for the sleep interval used during polling
    const POLL_SLEEP_INTERVAL: u64 = 50;

    /// Synchronously runs a polling loop over the supplied session. The run command performs
    /// periodic actions such as receiving messages, processing subscriptions, and recovering from
    /// connection errors. The run command will break if the session is disconnected
    /// and cannot be reestablished.
    ///
    /// The `run()` function returns a `Sender` that can be used to send a message to the session
    /// to cause it to terminate.
    ///
    /// # Arguments
    ///
    /// * `session` - the session to run ynchronously
    ///
    /// # Returns
    ///
    /// * `mpsc::Sender<ClientCommand>` - A sender that allows the caller to send a message to the
    ///                        run loop to cause it to stop.
    ///
    pub fn run(session: Arc<RwLock<Session>>) -> mpsc::Sender<SessionCommand> {
        let (tx, rx) = mpsc::channel();
        Self::run_loop(session, Self::POLL_SLEEP_INTERVAL, rx);
        tx
    }

    /// Asynchronously runs a polling loop over the supplied session. The run command performs
    /// periodic actions such as receiving messages, processing subscriptions, and recovering from
    /// connection errors. The run command will break if the session is disconnected
    /// and cannot be reestablished.
    ///
    /// The session runs on a separate thread so the call will return immediately.
    ///
    /// The `run()` function returns a `Sender` that can be used to send a message to the session
    /// to cause it to terminate.
    ///
    /// # Arguments
    ///
    /// * `session` - the session to run asynchronously
    ///
    /// # Returns
    ///
    /// * `mpsc::Sender<ClientCommand>` - A sender that allows the caller to send a message to the
    ///                        run loop to cause it to stop.
    ///
    pub fn run_async(session: Arc<RwLock<Session>>) -> mpsc::Sender<SessionCommand> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            Self::run_loop(session, Self::POLL_SLEEP_INTERVAL, rx)
        });
        tx
    }

    /// The main running loop for a session. This is used by `run()` and `run_async()` to run
    /// continuously until a signal is received to terminate.
    fn run_loop(session: Arc<RwLock<Session>>, sleep_interval: u64, rx: mpsc::Receiver<SessionCommand>) {
        loop {
            if let Ok(command) = rx.try_recv() {
                // Received a command
                match command {
                    SessionCommand::Stop => {
                        info!("Run session was terminated by a message");
                        break;
                    }
                }
            } else {
                // Poll the session.
                let poll_result = {
                    let mut session = session.write().unwrap();
                    session.poll()
                };
                match poll_result {
                    Ok(did_something) => {
                        // If the session did nothing, then sleep for a moment to save some CPU
                        if !did_something {
                            thread::sleep(Duration::from_millis(sleep_interval))
                        }
                    }
                    Err(_) => {
                        // Break the loop if connection goes down
                        info!("Connection to server broke, so terminating");
                        break;
                    }
                }
            }
        }
    }

    /// Polls on the session which basically dispatches any pending
    /// async responses, attempts to reconnect if the client is disconnected from the client and
    /// sleeps a little bit if nothing needed to be done.
    ///
    /// # Arguments
    ///
    /// * `sleep_for` - the period of time in milliseconds that poll should sleep for if it performed
    ///                 no action.
    ///
    /// # Returns
    ///
    /// * `true` - if an action was performed during the poll
    /// * `false` - if no action was performed during the poll and the poll slept
    ///
    pub fn poll(&mut self) -> Result<bool, ()> {
        let did_something = if self.is_connected() {
            self.handle_publish_responses()
        } else {
            use chrono::Utc;
            match self.session_retry_policy.should_retry_connect(Utc::now()) {
                Answer::GiveUp => {
                    session_error!(self, "Session has given up trying to reconnect to the server after {} retries", self.session_retry_policy.retry_count());
                    return Err(());
                }
                Answer::Retry => {
                    info!("Retrying to reconnect to server...");
                    self.session_retry_policy.set_last_attempt(Utc::now());
                    if self.reconnect_and_activate().is_ok() {
                        info!("Retry to connect was successful");
                        self.session_retry_policy.reset_retry_count();
                    } else {
                        self.session_retry_policy.increment_retry_count();
                        session_warn!(self, "Reconnect was unsuccessful, retries = {}", self.session_retry_policy.retry_count());
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
        Ok(did_something)
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Discovery Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Sends a [`FindServersRequest`] to the server denoted by the discovery url.
    ///
    /// See OPC UA Part 4 - Services 5.4.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `endpoint_url` - The network address that the Client used to access the Discovery Endpoint.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ApplicationDescription>)` - A list of [`ApplicationDescription`] that meet criteria specified in the request.
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`FindServersRequest`]: ./struct.FindServersRequest.html
    /// [`ApplicationDescription`]: ./struct.ApplicationDescription.html
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

    /// Obtain the list of endpoints supported by the server by sending it a [`GetEndpointsRequest`].
    ///
    /// See OPC UA Part 4 - Services 5.4.4 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<EndpointDescription>)` - A list of endpoints supported by the server
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`GetEndpointsRequest`]: ./struct.GetEndpointsRequest.html
    ///
    pub fn get_endpoints(&mut self) -> Result<Vec<EndpointDescription>, StatusCode> {
        session_debug!(self, "get_endpoints");
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
            match response.endpoints {
                None => {
                    session_debug!(self, "get_endpoints, success but no endpoints");
                    Ok(Vec::new())
                }
                Some(endpoints) => {
                    session_debug!(self, "get_endpoints, success");
                    Ok(endpoints)
                }
            }
        } else {
            session_error!(self, "get_endpoints failed {:?}", response);
            Err(crate::process_unexpected_response(response))
        }
    }

    /// This function is used by servers that wish to register themselves with a discovery server.
    /// i.e. one server is the client to another server. The server sends a [`RegisterServerRequest`]
    /// to the discovery server to register itself. Servers are expected to re-register themselves periodically
    /// with the discovery server, with a maximum of 10 minute intervals.
    ///
    /// See OPC UA Part 4 - Services 5.4.5 for complete description of the service and error responses.
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
    /// [`RegisterServerRequest`]: ./struct.RegisterServerRequest.html
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

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // SecureChannel Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Sends an [`OpenSecureChannelRequest`] to the server
    ///
    ///
    /// See OPC UA Part 4 - Services 5.5.2 for complete description of the service and error responses.
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`OpenSecureChannelRequest`]: ./struct.OpenSecureChannelRequest.html
    ///
    pub fn open_secure_channel(&mut self) -> Result<(), StatusCode> {
        session_debug!(self, "open_secure_channel");
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.issue_or_renew_secure_channel(SecurityTokenRequestType::Issue)
    }

    /// Sends a [`CloseSecureChannelRequest`] to the server which will cause the server to drop
    /// the connection.
    ///
    /// See OPC UA Part 4 - Services 5.5.3 for complete description of the service and error responses.
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

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Session Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Sends a [`CreateSessionRequest`] to the server, returning the session id of the created
    /// session. Internally, the session will store the authentication token which is used for requests
    /// subsequent to this call.
    ///
    /// See OPC UA Part 4 - Services 5.6.2 for complete description of the service and error responses.
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
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();

        let client_nonce = {
            let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
            secure_channel.local_nonce_as_byte_string()
        };

        let server_uri = UAString::null();
        let session_name = UAString::from("Rust OPCUA Client");

        let (client_certificate, _) = {
            let certificate_store = trace_write_lock_unwrap!(self.certificate_store);
            certificate_store.read_own_cert_and_pkey_optional()
        };

        // Security
        let client_certificate = if let Some(ref client_certificate) = client_certificate {
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

        session_debug!(self, "CreateSessionRequest = {:?}", request);

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

            // session_debug!(self, "Server nonce is {:?}", response.server_nonce);

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
                    session_error!(self, "Server did not supply a valid X509 certificate");
                    StatusCode::BadCertificateInvalid
                }
            } else {
                StatusCode::Good
            };

            if !cert_status_code.is_good() {
                session_error!(self, "Server's certificate was rejected");
                Err(cert_status_code)
            } else {
                // Spawn a task to ping the server to keep the connection alive before the session
                // timeout period.
                session_debug!(self, "Revised session timeout is {}", response.revised_session_timeout);
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
        session_debug!(self, "spawn_session_activity_task({})", session_timeout);

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
        session_debug!(self, "session timeout is {}, activity timer is {}", session_timeout, session_activity);

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
            tokio::run(task);
        });
    }

    /// Sends an [`ActivateSessionRequest`] to the server to activate this session
    ///
    /// See OPC UA Part 4 - Services 5.6.3 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`ActivateSessionRequest`]: ./struct.ActivateSessionRequest.html
    ///
    pub fn activate_session(&mut self) -> Result<(), StatusCode> {
        let (user_identity_token, user_token_signature) = {
            let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
            self.user_identity_token(&secure_channel.remote_cert(), secure_channel.remote_nonce())?
        };

        let locale_ids = if self.session_info.preferred_locales.is_empty() {
            None
        } else {
            // Ids are
            let locale_ids = self.session_info.preferred_locales.iter().map(|id| UAString::from(id)).collect();
            Some(locale_ids)
        };

        let security_policy = self.security_policy();
        let client_signature = match security_policy {
            SecurityPolicy::None => SignatureData::null(),
            _ => {
                let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
                let server_cert = secure_channel.remote_cert();
                let server_nonce = secure_channel.remote_nonce();

                let (_, client_pkey) = {
                    let certificate_store = trace_write_lock_unwrap!(self.certificate_store);
                    certificate_store.read_own_cert_and_pkey_optional()
                };


                // Create a signature data
                // let session_state = self.session_state.lock().unwrap();
                if client_pkey.is_none() {
                    session_error!(self, "Cannot create client signature - no pkey!");
                    return Err(StatusCode::BadUnexpectedError);
                } else if server_cert.is_none() {
                    session_error!(self, "Cannot sign server certificate because server cert is null");
                    return Err(StatusCode::BadUnexpectedError);
                } else if server_nonce.is_empty() {
                    session_error!(self, "Cannot sign server certificate because server nonce is empty");
                    return Err(StatusCode::BadUnexpectedError);
                }

                let server_cert = secure_channel.remote_cert().as_ref().unwrap().as_byte_string();
                let server_nonce = ByteString::from(secure_channel.remote_nonce());
                let signing_key = client_pkey.as_ref().unwrap();
                crypto::create_signature_data(signing_key, security_policy, &server_cert, &server_nonce)?
            }
        };

        let client_software_certificates = None;

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

    /// Cancels an outstanding service request by sending a [`CancelRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.6.5 for complete description of the service and error responses.
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

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // NodeManagement Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Add nodes by sending a [`AddNodesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_add` - A list of [`AddNodesItem`] to be added to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<AddNodesResult>)` - A list of [`AddNodesResult`] corresponding to each add node operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`AddNodesRequest`]: ./struct.AddNodesRequest.html
    /// [`AddNodesItem`]: ./struct.AddNodesItem.html
    /// [`AddNodesResult`]: ./struct.AddNodesResult.html
    ///
    pub fn add_nodes(&mut self, nodes_to_add: &[AddNodesItem]) -> Result<Vec<AddNodesResult>, StatusCode> {
        if nodes_to_add.is_empty() {
            session_error!(self, "add_nodes, called with no nodes to add");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = AddNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_add: Some(nodes_to_add.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::AddNodesResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Add references by sending a [`AddReferencesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `references_to_add` - A list of [`AddReferencesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each add reference operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`AddReferencesRequest`]: ./struct.AddReferencesRequest.html
    /// [`AddReferencesItem`]: ./struct.AddReferencesItem.html
    ///
    pub fn add_references(&mut self, references_to_add: &[AddReferencesItem]) -> Result<Vec<StatusCode>, StatusCode> {
        if references_to_add.is_empty() {
            session_error!(self, "add_references, called with no references to add");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = AddReferencesRequest {
                request_header: self.make_request_header(),
                references_to_add: Some(references_to_add.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::AddReferencesResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Delete nodes by sending a [`DeleteNodesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_delete` - A list of [`DeleteNodesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each delete node operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`DeleteNodesRequest`]: ./struct.DeleteNodesRequest.html
    /// [`DeleteNodesItem`]: ./struct.DeleteNodesItem.html
    ///
    pub fn delete_nodes(&mut self, nodes_to_delete: &[DeleteNodesItem]) -> Result<Vec<StatusCode>, StatusCode> {
        if nodes_to_delete.is_empty() {
            session_error!(self, "delete_nodes, called with no nodes to delete");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = DeleteNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_delete: Some(nodes_to_delete.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::DeleteNodesResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Delete references by sending a [`DeleteReferencesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_delete` - A list of [`DeleteReferencesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each delete node operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`DeleteReferencesRequest`]: ./struct.DeleteReferencesRequest.html
    /// [`DeleteReferencesItem`]: ./struct.DeleteReferencesItem.html
    ///
    pub fn delete_references(&mut self, references_to_delete: &[DeleteReferencesItem]) -> Result<Vec<StatusCode>, StatusCode> {
        if references_to_delete.is_empty() {
            session_error!(self, "delete_references, called with no references to delete");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = DeleteReferencesRequest {
                request_header: self.make_request_header(),
                references_to_delete: Some(references_to_delete.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::DeleteReferencesResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // View Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Discover the references to the specified nodes by sending a [`BrowseRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.8.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_browse` - A list of [`BrowseDescription`] describing nodes to browse.
    ///
    /// # Returns
    ///
    /// * `Ok(Option<Vec<BrowseResult>)` - A list [`BrowseResult`] corresponding to each node to browse. A browse result
    ///                                    may contain a continuation point, for use with `browse_next()`.
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`BrowseRequest`]: ./struct.BrowseRequest.html
    /// [`BrowseDescription`]: ./struct.BrowseDescription.html
    /// [`BrowseResult`]: ./struct.BrowseResult.html
    ///
    pub fn browse(&mut self, nodes_to_browse: &[BrowseDescription]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if nodes_to_browse.is_empty() {
            session_error!(self, "browse, was not supplied with any nodes to browse");
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
                session_debug!(self, "browse, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                session_error!(self, "browse failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Continue to discover references to nodes by sending continuation points in a [`BrowseNextRequest`]
    /// to the server. This function may have to be called repeatedly to process the initial query.
    ///
    /// See OPC UA Part 4 - Services 5.8.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `release_continuation_points` - Flag indicating if the continuation points should be released by the server
    /// * `continuation_points` - A list of [`BrowseDescription`] continuation points
    ///
    /// # Returns
    ///
    /// * `Ok(Option<Vec<BrowseResult>)` - A list [`BrowseResult`] corresponding to each node to browse. A browse result
    ///                                    may contain a continuation point, for use with `browse_next()`.
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`BrowseRequest`]: ./struct.BrowseRequest.html
    /// [`BrowseNextRequest`]: ./struct.BrowseNextRequest.html
    /// [`BrowseResult`]: ./struct.BrowseResult.html
    ///
    pub fn browse_next(&mut self, release_continuation_points: bool, continuation_points: &[ByteString]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if continuation_points.is_empty() {
            session_error!(self, "browse_next, was not supplied with any continuation points");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = BrowseNextRequest {
                request_header: self.make_request_header(),
                continuation_points: Some(continuation_points.to_vec()),
                release_continuation_points,
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::BrowseNextResponse(response) = response {
                session_debug!(self, "browse_next, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                session_error!(self, "browse_next failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Register nodes on the server by sending a [`RegisterNodesRequest`]. The purpose of this
    /// call is server-dependent but allows a client to ask a server to create nodes which are
    /// otherwise expensive to set up or maintain, e.g. nodes attached to hardware.
    ///
    /// See OPC UA Part 4 - Services 5.8.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_register` - A list of [`NodeId`] nodes for the server to register
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<NodeId>)` - A list of [`NodeId`] corresponding to size and order of the input. The
    ///                       server may return an alias for the input `NodeId`
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`RegisterNodesRequest`]: ./struct.RegisterNodesRequest.html
    /// [`NodeId`]: ./struct.NodeId.html
    pub fn register_nodes(&mut self, nodes_to_register: &[NodeId]) -> Result<Vec<NodeId>, StatusCode> {
        if nodes_to_register.is_empty() {
            session_error!(self, "register_nodes, was not supplied with any nodes to register");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = RegisterNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_register: Some(nodes_to_register.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::RegisterNodesResponse(response) = response {
                session_debug!(self, "register_nodes, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.registered_node_ids.unwrap())
            } else {
                session_error!(self, "register_nodes failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Unregister nodes on the server by sending a [`UnregisterNodesRequest`]. This indicates to
    /// the server that the client relinquishes any need for these nodes. The server will ignore
    /// unregistered nodes.
    ///
    /// See OPC UA Part 4 - Services 5.8.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_unregister` - A list of [`NodeId`] nodes for the server to unregister
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Request succeeded, server ignores invalid nodes
    /// * `Err(StatusCode)` - Request failed, status code is the reason for failure
    ///
    /// [`UnregisterNodesRequest`]: ./struct.UnregisterNodesRequest.html
    /// [`NodeId`]: ./struct.NodeId.html
    ///
    pub fn unregister_nodes(&mut self, nodes_to_unregister: &[NodeId]) -> Result<(), StatusCode> {
        if nodes_to_unregister.is_empty() {
            session_error!(self, "unregister_nodes, was not supplied with any nodes to unregister");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = UnregisterNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_unregister: Some(nodes_to_unregister.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::UnregisterNodesResponse(response) = response {
                session_debug!(self, "unregister_nodes, success");
                crate::process_service_result(&response.response_header)?;
                Ok(())
            } else {
                session_error!(self, "unregister_nodes failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Attribute Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Reads the value of nodes by sending a [`ReadRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.10.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_read` - A list of [`ReadValueId`] to be read by the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<DataValue>)` - A list of [`DataValue`] corresponding to each read operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`ReadRequest`]: ./struct.ReadRequest.html
    /// [`ReadValueId`]: ./struct.ReadValueId.html
    /// [`DataValue`]: ./struct.DataValue.html
    ///
    pub fn read(&mut self, nodes_to_read: &[ReadValueId]) -> Result<Option<Vec<DataValue>>, StatusCode> {
        if nodes_to_read.is_empty() {
            // No subscriptions
            session_error!(self, "read_nodes, was not supplied with any nodes to read");
            Err(StatusCode::BadNothingToDo)
        } else {
            session_debug!(self, "read_nodes requested to read nodes {:?}", nodes_to_read);
            let request = ReadRequest {
                request_header: self.make_request_header(),
                max_age: 1f64,
                timestamps_to_return: TimestampsToReturn::Server,
                nodes_to_read: Some(nodes_to_read.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::ReadResponse(response) = response {
                session_debug!(self, "read_nodes, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                session_error!(self, "read() value failed");
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Writes values to nodes by sending a [`WriteRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.10.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_write` - A list of [`WriteValue`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` results corresponding to each write operation.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`WriteRequest`]: ./struct.WriteRequest.html
    /// [`WriteValue`]: ./struct.WriteValue.html
    ///
    pub fn write(&mut self, nodes_to_write: &[WriteValue]) -> Result<Option<Vec<StatusCode>>, StatusCode> {
        if nodes_to_write.is_empty() {
            // No subscriptions
            session_error!(self, "write_value() was not supplied with any nodes to write");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = WriteRequest {
                request_header: self.make_request_header(),
                nodes_to_write: Some(nodes_to_write.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::WriteResponse(response) = response {
                session_debug!(self, "write_value, success");
                crate::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                session_error!(self, "write_value failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Method Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Calls a single method on an object on the server by sending a [`CallRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.11.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `method` - The method to call. Note this function takes anything that can be turned into
    ///   a [`CallMethodRequest`] which includes a (`NodeId`, `NodeId`, `Option<Vec<Variant>>`)
    ///   which refers to the object id, method id, and input arguments respectively.
    /// * `items_to_delete` - List of Server-assigned ids for the MonitoredItems to be deleted.
    ///
    /// # Returns
    ///
    /// * `Ok(CallMethodResult)` - A `[CallMethodResult]` for the Method call.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`CallRequest`]: ./struct.CallRequest.html
    /// [`CallMethodRequest`]: ./struct.CallMethodRequest.html
    /// [`CallMethodResult`]: ./struct.CallMethodResult.html
    ///
    pub fn call<T>(&mut self, method: T) -> Result<CallMethodResult, StatusCode> where T: Into<CallMethodRequest> {
        session_debug!(self, "call_method");
        let methods_to_call = Some(vec![method.into()]);
        let request = CallRequest {
            request_header: self.make_request_header(),
            methods_to_call,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::CallResponse(response) = response {
            if let Some(mut results) = response.results {
                if results.len() != 1 {
                    session_error!(self, "call_method, expecting a result from the call to the server, got {} results", results.len());
                    Err(StatusCode::BadUnexpectedError)
                } else {
                    Ok(results.remove(0))
                }
            } else {
                session_error!(self, "call_method, expecting a result from the call to the server, got nothing");
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
        let response = self.call(request)?;
        if let Some(mut result) = response.output_arguments {
            if result.len() == 2 {
                let server_handles = <Vec<u32>>::try_from(&result.remove(0)).map_err(|_| StatusCode::BadUnexpectedError)?;
                let client_handles = <Vec<u32>>::try_from(&result.remove(0)).map_err(|_| StatusCode::BadUnexpectedError)?;
                Ok((server_handles, client_handles))
            } else {
                session_error!(self, "Expected a result with 2 args and didn't get it.");
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            session_error!(self, "Expected a result and didn't get it.");
            Err(StatusCode::BadUnexpectedError)
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // MonitoredItem Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Creates monitored items on a subscription by sending a [`CreateMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_create` - A list of [`MonitoredItemCreateRequest`] to be created and assigned to the specified Subscription.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemCreateResult>)` - A list of [`MonitoredItemCreateResult`] corresponding to the items to create.
    ///    The size and order of the list matches the size and order of the `items_to_create` request parameter.
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`CreateMonitoredItemsRequest`]: ./struct.CreateMonitoredItemsRequest.html
    /// [`MonitoredItemCreateRequest`]: ./struct.MonitoredItemCreateRequest.html
    /// [`MonitoredItemCreateResult`]: ./struct.MonitoredItemCreateResult.html
    ///
    pub fn create_monitored_items(&mut self, subscription_id: u32, timestamps_to_return: TimestampsToReturn, items_to_create: &[MonitoredItemCreateRequest]) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        session_debug!(self, "create_monitored_items, for subscription {}, {} items", subscription_id, items_to_create.len());
        if subscription_id == 0 {
            session_error!(self, "create_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(self, "create_monitored_items, subscription id {} does not exist", subscription_id);
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_create.is_empty() {
            session_error!(self, "create_monitored_items, called with no items to create");
            Err(StatusCode::BadNothingToDo)
        } else {
            // Assign each item a unique client handle
            let mut items_to_create = items_to_create.to_vec();
            {
                let mut session_state = trace_write_lock_unwrap!(self.session_state);
                items_to_create.iter_mut().for_each(|i| {
                    //if user doesn't specify a valid client_handle
                    if i.requested_parameters.client_handle == 0 {
                        i.requested_parameters.client_handle = session_state.next_monitored_item_handle();
                    }
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
                    session_debug!(self, "create_monitored_items, {} items created", items_to_create.len());
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
                    session_debug!(self, "create_monitored_items, success but no monitored items were created");
                }
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "create_monitored_items failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Modifies monitored items on a subscription by sending a [`ModifyMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_modify` - The list of [`MonitoredItemModifyRequest`] to modify.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemModifyResult>)` - A list of [`MonitoredItemModifyResult`] corresponding to the MonitoredItems to modify.
    ///    The size and order of the list matches the size and order of the `items_to_modify` request parameter.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`ModifyMonitoredItemsRequest`]: ./struct.ModifyMonitoredItemsRequest.html
    /// [`MonitoredItemModifyRequest`]: ./struct.MonitoredItemModifyRequest.html
    /// [`MonitoredItemModifyResult`]: ./struct.MonitoredItemModifyResult.html
    ///
    pub fn modify_monitored_items(&mut self, subscription_id: u32, timestamps_to_return: TimestampsToReturn, items_to_modify: &[MonitoredItemModifyRequest]) -> Result<Vec<MonitoredItemModifyResult>, StatusCode> {
        session_debug!(self, "modify_monitored_items, for subscription {}, {} items", subscription_id, items_to_modify.len());
        if subscription_id == 0 {
            session_error!(self, "modify_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(self, "modify_monitored_items, subscription id {} does not exist", subscription_id);
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_modify.is_empty() {
            session_error!(self, "modify_monitored_items, called with no items to modify");
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
                session_debug!(self, "modify_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "modify_monitored_items failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Sets the monitoring mode on one or more monitored items by sending a [`SetMonitoringModeRequest`]
    /// to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored items to be modified.
    /// * `monitoring_mode` - the monitored mode to apply to the monitored items
    /// * `monitored_item_ids` - the monitored items to be modified
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - Individual result for each monitored item.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`SetMonitoringModeRequest`]: ./struct.SetMonitoringModeRequest.html
    ///
    pub fn set_monitoring_mode(&mut self, subscription_id: u32, monitoring_mode: MonitoringMode, monitored_item_ids: &[u32]) -> Result<Vec<StatusCode>, StatusCode> {
        if monitored_item_ids.is_empty() {
            session_error!(self, "set_monitoring_mode, called with nothing to do");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = {
                let monitored_item_ids = Some(monitored_item_ids.to_vec());
                SetMonitoringModeRequest {
                    request_header: self.make_request_header(),
                    subscription_id,
                    monitoring_mode,
                    monitored_item_ids,
                }
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::SetMonitoringModeResponse(response) = response {
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "set_monitoring_mode failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Sets a monitored item so it becomes the trigger that causes other monitored items to send
    /// change events in the same update. Sends a [`SetTriggeringRequest`] to the server.
    /// Note that `items_to_remove` is applied before `items_to_add`.
    ///
    /// See OPC UA Part 4 - Services 5.12.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored item to be used as the trigger.
    /// * `monitored_item_id` - the monitored item that is the trigger.
    /// * `links_to_add` - zero or more items to be added to the monitored item's triggering list.
    /// * `items_to_remove` - zero or more items to be removed from the monitored item's triggering list.
    ///
    /// # Returns
    ///
    /// * `Ok((Option<Vec<StatusCode>>, Option<Vec<StatusCode>>))` - Individual result for each item added / removed for the SetTriggering call.
    /// * `Err(StatusCode)` - Status code reason for failure.
    ///
    /// [`SetTriggeringRequest`]: ./struct.SetTriggeringRequest.html
    ///
    pub fn set_triggering(&mut self, subscription_id: u32, triggering_item_id: u32, links_to_add: &[u32], links_to_remove: &[u32]) -> Result<(Option<Vec<StatusCode>>, Option<Vec<StatusCode>>), StatusCode> {
        if links_to_add.is_empty() && links_to_remove.is_empty() {
            session_error!(self, "set_triggering, called with nothing to add or remove");
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
                // Update client side state
                let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                subscription_state.set_triggering(subscription_id, triggering_item_id, links_to_add, links_to_remove);
                Ok((response.add_results, response.remove_results))
            } else {
                session_error!(self, "set_triggering failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Deletes monitored items from a subscription by sending a [`DeleteMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.6 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `items_to_delete` - List of Server-assigned ids for the MonitoredItems to be deleted.
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
        session_debug!(self, "delete_monitored_items, subscription {} for {} items", subscription_id, items_to_delete.len());
        if subscription_id == 0 {
            session_error!(self, "delete_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(self, "delete_monitored_items, subscription id {} does not exist", subscription_id);
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_delete.is_empty() {
            session_error!(self, "delete_monitored_items, called with no items to delete");
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
                if response.results.is_some() {
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.delete_monitored_items(subscription_id, items_to_delete);
                }
                session_debug!(self, "delete_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "delete_monitored_items failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Subscription Service set
    ////////////////////////////////////////////////////////////////////////////////////////////////

    /// Create a subscription by sending a [`CreateSubscriptionRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.2 for complete description of the service and error responses.
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
        where CB: OnSubscriptionNotification + Send + Sync + 'static {
        self.create_subscription_inner(publishing_interval, lifetime_count, max_keep_alive_count, max_notifications_per_publish, priority, publishing_enabled, Arc::new(Mutex::new(callback)))
    }

    /// This is the internal handler for create subscription that receives the callback wrapped up and reference counted.
    fn create_subscription_inner(&mut self, publishing_interval: f64, lifetime_count: u32, max_keep_alive_count: u32, max_notifications_per_publish: u32,
                                 priority: u8, publishing_enabled: bool,
                                 callback: Arc<Mutex<dyn OnSubscriptionNotification + Send + Sync + 'static>>)
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
            session_debug!(self, "create_subscription, created a subscription with id {}", response.subscription_id);
            Ok(response.subscription_id)
        } else {
            session_error!(self, "create_subscription failed {:?}", response);
            Err(crate::process_unexpected_response(response))
        }
    }

    /// Modifies a subscription by sending a [`ModifySubscriptionRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.3 for complete description of the service and error responses.
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
            session_error!(self, "modify_subscription, subscription id must be non-zero, or the subscription is considered invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(self, "modify_subscription, subscription id does not exist");
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
                session_debug!(self, "modify_subscription success for {}", subscription_id);
                Ok(())
            } else {
                session_error!(self, "modify_subscription failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Changes the publishing mode of subscriptions by sending a [`SetPublishingModeRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.4 for complete description of the service and error responses.
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
        session_debug!(self, "set_publishing_mode, for subscriptions {:?}, publishing enabled {}", subscription_ids, publishing_enabled);
        if subscription_ids.is_empty() {
            // No subscriptions
            session_error!(self, "set_publishing_mode, no subscription ids were provided");
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
                session_debug!(self, "set_publishing_mode success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "set_publishing_mode failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Transfers Subscriptions and their MonitoredItems from one Session to another. For example,
    /// a Client may need to reopen a Session and then transfer its Subscriptions to that Session.
    /// It may also be used by one Client to take over a Subscription from another Client by
    /// transferring the Subscription to its Session.
    ///
    /// See OPC UA Part 4 - Services 5.13.7 for complete description of the service and error responses.
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `send_initial_values` - A boolean parameter with the following values - `true` the first
    ///   publish response shall contain the current values of all monitored items in the subscription,
    ///   `false`, the first publish response shall contain only the value changes since the last
    ///   publish response was sent.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<TransferResult>)` - The [`TransferResult`] for each transfer subscription.
    /// * `Err(StatusCode)` - Status code reason for failure
    ///
    /// [`TransferSubscriptionsRequest`]: ./struct.TransferSubscriptionsRequest.html
    /// [`TransferResult`]: ./struct.TransferResult.html
    ///
    pub fn transfer_subscriptions(&mut self, subscription_ids: &[u32], send_initial_values: bool) -> Result<Vec<TransferResult>, StatusCode> {
        if subscription_ids.is_empty() {
            // No subscriptions
            session_error!(self, "set_publishing_mode, no subscription ids were provided");
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
                session_debug!(self, "transfer_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "transfer_subscriptions failed {:?}", response);
                Err(crate::process_unexpected_response(response))
            }
        }
    }

    /// Deletes a subscription by sending a [`DeleteSubscriptionsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
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
            session_error!(self, "delete_subscription, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(self, "delete_subscription, subscription id {} does not exist", subscription_id);
            Err(StatusCode::BadInvalidArgument)
        } else {
            let result = self.delete_subscriptions(&[subscription_id][..])?;
            Ok(result[0])
        }
    }

    /// Deletes subscriptions by sending a [`DeleteSubscriptionsRequest`] to the server with the list
    /// of subscriptions to delete.
    ///
    /// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
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
            session_trace!(self, "delete_subscriptions with no subscriptions");
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
                session_debug!(self, "delete_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "delete_subscriptions failed {:?}", response);
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
            let status_codes = self.delete_subscriptions(subscription_ids.as_slice())?;
            // Return a list of (id, status_code) for each subscription
            Ok(subscription_ids.iter().zip(status_codes).map(|(id, status_code)| (*id, status_code)).collect())
        } else {
            // No subscriptions
            session_trace!(self, "delete_all_subscriptions, called when there are no subscriptions");
            Err(StatusCode::BadNothingToDo)
        }
    }

    /// Returns the subscription state object
    pub fn subscription_state(&self) -> Arc<RwLock<SubscriptionState>> {
        self.subscription_state.clone()
    }

    /// Returns a string identifier for the session
    pub(crate) fn session_id(&self) -> String {
        let session_state = self.session_state();
        let session_state = session_state.read().unwrap();
        format!("session:{}", session_state.id())
    }

    /// Notify any callback of the connection status change
    fn on_connection_status_change(&mut self, connected: bool) {
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.on_connection_status_change(connected);
    }

    /// Returns the security policy
    fn security_policy(&self) -> SecurityPolicy {
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        secure_channel.security_policy()
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

    // Creates a user identity token according to the endpoint, policy that the client is currently connected to the
    // server with.
    fn user_identity_token(&self, server_cert: &Option<X509>, server_nonce: &[u8]) -> Result<(ExtensionObject, SignatureData), StatusCode> {
        let user_identity_token = &self.session_info.user_identity_token;
        let user_token_type = match user_identity_token {
            &client::IdentityToken::Anonymous => UserTokenType::Anonymous,
            &client::IdentityToken::UserName(_, _) => UserTokenType::UserName,
            &client::IdentityToken::X509(_, _) => UserTokenType::Certificate,
        };

        let endpoint = &self.session_info.endpoint;
        let policy = endpoint.find_policy(user_token_type);
        session_debug!(self, "Endpoint policy = {:?}", policy);

        // Return the result
        match policy {
            None => {
                session_error!(self, "Cannot find user token type {:?} for this endpoint, cannot connect", user_token_type);
                Err(StatusCode::BadSecurityPolicyRejected)
            }
            Some(policy) => {
                let security_policy = if policy.security_policy_uri.is_null() {
                    // Assume None
                    SecurityPolicy::None
                } else {
                    SecurityPolicy::from_uri(policy.security_policy_uri.as_ref())
                };
                if security_policy == SecurityPolicy::Unknown {
                    session_error!(self, "Can't support the security policy {}", policy.security_policy_uri);
                    Err(StatusCode::BadSecurityPolicyRejected)
                } else {
                    match user_identity_token {
                        &client::IdentityToken::Anonymous => {
                            let identity_token = AnonymousIdentityToken {
                                policy_id: policy.policy_id.clone(),
                            };
                            let identity_token = ExtensionObject::from_encodable(ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary, &identity_token);
                            Ok((identity_token, SignatureData::null()))
                        }
                        &client::IdentityToken::UserName(ref user, ref pass) => {
                            let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
                            let identity_token = self.make_user_name_identity_token(&secure_channel, policy, user, pass)?;
                            let identity_token = ExtensionObject::from_encodable(ObjectId::UserNameIdentityToken_Encoding_DefaultBinary, &identity_token);
                            Ok((identity_token, SignatureData::null()))
                        }
                        &client::IdentityToken::X509(ref cert_path, ref private_key_path) => {
                            if let Some(ref server_cert) = server_cert {
                                // The cert will be supplied to the server along with a signature to prove we have the private key to go with the cert
                                let certificate_data = CertificateStore::read_cert(cert_path).map_err(|e| {
                                    session_error!(self, "Certificate cannot be loaded from path {}, error = {}", cert_path.to_str().unwrap(), e);
                                    StatusCode::BadSecurityPolicyRejected
                                })?;
                                let private_key = CertificateStore::read_pkey(private_key_path).map_err(|e| {
                                    session_error!(self, "Private key cannot be loaded from path {}, error = {}", private_key_path.to_str().unwrap(), e);
                                    StatusCode::BadSecurityPolicyRejected
                                })?;

                                // Create a signature using the X509 private key to sign the server's cert and nonce
                                let user_token_signature = crypto::create_signature_data(&private_key, security_policy, &server_cert.as_byte_string(), &ByteString::from(server_nonce))?;

                                // Create identity token
                                let identity_token = X509IdentityToken {
                                    policy_id: policy.policy_id.clone(),
                                    certificate_data: certificate_data.as_byte_string(),
                                };
                                let identity_token = ExtensionObject::from_encodable(ObjectId::X509IdentityToken_Encoding_DefaultBinary, &identity_token);

                                Ok((identity_token, user_token_signature))
                            } else {
                                session_error!(self, "Cannot create an X509IdentityToken because the remote server has no cert with which to create a signature");
                                Err(StatusCode::BadCertificateInvalid)
                            }
                        }
                    }
                }
            }
        }
    }

    /// Create a filled in UserNameIdentityToken by using the endpoint's token policy, the current
    /// secure channel information and the user name and password.
    fn make_user_name_identity_token(&self, secure_channel: &SecureChannel, user_token_policy: &UserTokenPolicy, user: &str, pass: &str) -> Result<UserNameIdentityToken, StatusCode> {
        let channel_security_policy = secure_channel.security_policy();
        let nonce = secure_channel.remote_nonce();
        let cert = secure_channel.remote_cert();
        make_user_name_identity_token(channel_security_policy, user_token_policy, nonce, &cert, user, pass)
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
        let mut wait_for_publish_response = false;
        match response {
            SupportedMessage::PublishResponse(response) => {
                session_debug!(self, "PublishResponse");

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
                if let Some((data_change_notifications, events)) = notification_message.notifications(&decoding_limits) {
                    session_debug!(self, "Received notifications, data changes = {}, events = {}", data_change_notifications.len(), events.len());
                    if !data_change_notifications.is_empty() {
                        let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                        subscription_state.on_data_change(subscription_id, &data_change_notifications);
                    }
                    if !events.is_empty() {
                        let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                        subscription_state.on_event(subscription_id, &events);
                    }
                }
            }
            SupportedMessage::ServiceFault(response) => {
                let service_result = response.response_header.service_result;
                session_debug!(self, "Service fault received with {} error code", service_result);
                session_trace!(self, "ServiceFault {:?}", response);
                // Terminate timer if
                if service_result == StatusCode::BadTooManyPublishRequests {
                    // Turn off publish requests until server says otherwise
                    wait_for_publish_response = false;
                }
            }
            _ => {
                info!("{} unhandled response", self.session_id());
            }
        }

        // Turn on/off publish requests
        {
            let mut session_state = trace_write_lock_unwrap!(self.session_state);
            session_state.set_wait_for_publish_response(wait_for_publish_response);
        }
    }
}
