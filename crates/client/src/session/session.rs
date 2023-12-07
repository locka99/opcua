// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Session functionality for the current open client connection. This module contains functions
//! to call for all typically synchronous operations during an OPC UA session.
//!
//! The session also has async functionality but that is reserved for publish requests on subscriptions
//! and events.
use std::{
    cmp,
    collections::HashSet,
    result::Result,
    str::FromStr,
    sync::{mpsc::SyncSender, Arc},
    time::Duration,
};

use parking_lot::{Mutex, RwLock};
use tokio::{
    sync::oneshot,
    time::{interval, Instant},
};

use crate::{
    callbacks::{OnConnectionStatusChange, OnSessionClosed, OnSubscriptionNotification},
    client::IdentityToken,
    message_queue::MessageQueue,
    process_service_result, process_unexpected_response,
    session::{
        services::*,
        session_debug, session_error,
        session_state::{ConnectionState, SessionState},
        session_trace, session_warn,
    },
    session_retry_policy::{Answer, SessionRetryPolicy},
    subscription::{self, Subscription},
    subscription_state::SubscriptionState,
};

use opcua_core::{
    comms::{
        secure_channel::{Role, SecureChannel},
        url::*,
    },
    crypto::{
        self as crypto, user_identity::make_user_name_identity_token, CertificateStore,
        SecurityPolicy, X509,
    },
    supported_message::SupportedMessage,
    types::{node_ids::ObjectId, status_code::StatusCode, *},
};

/// Information about the server endpoint, security policy, security mode and user identity that the session will
/// will use to establish a connection.
#[derive(Debug)]
pub struct SessionInfo {
    /// The endpoint
    pub endpoint: EndpointDescription,
    /// User identity token
    pub user_identity_token: IdentityToken,
    /// Preferred language locales
    pub preferred_locales: Vec<String>,
}

impl From<EndpointDescription> for SessionInfo {
    fn from(val: EndpointDescription) -> Self {
        (val, IdentityToken::Anonymous).into()
    }
}

impl From<(EndpointDescription, IdentityToken)> for SessionInfo {
    fn from(val: (EndpointDescription, IdentityToken)) -> Self {
        SessionInfo {
            endpoint: val.0,
            user_identity_token: val.1,
            preferred_locales: Vec::new(),
        }
    }
}

/// A `Session` runs in a loop, which can be terminated by sending it a `SessionCommand`.
#[derive(Debug)]
pub enum SessionCommand {
    /// Stop running as soon as possible
    Stop,
}

/// A session of the client. The session is associated with an endpoint and maintains a state
/// when it is active. The `Session` struct provides functions for all the supported
/// request types in the API.
///
/// Note that not all servers may support all service requests and calling an unsupported API
/// may cause the connection to be dropped. Your client is expected to know the capabilities of
/// the server it is calling to avoid this.
pub struct Session {
    /// The client application's name.
    application_description: ApplicationDescription,
    /// A name for the session, supplied during create
    session_name: UAString,
    /// The session connection info.
    session_info: SessionInfo,
    /// Runtime state of the session, reset if disconnected.
    session_state: Arc<RwLock<SessionState>>,
    /// Certificate store.
    certificate_store: CertificateStore,
    /// Session retry policy.
    session_retry_policy: Arc<Mutex<SessionRetryPolicy>>,
    message_queue: Arc<RwLock<MessageQueue>>,
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
    pub(crate) fn new<T>(
        application_description: ApplicationDescription,
        session_name: T,
        certificate_store: CertificateStore,
        session_info: SessionInfo,
        session_retry_policy: SessionRetryPolicy,
        decoding_options: DecodingOptions,
        ignore_clock_skew: bool,
    ) -> Session
    where
        T: Into<UAString>,
    {
        let session_name = session_name.into();

        let secure_channel = SecureChannel::new(&certificate_store, Role::Client, decoding_options);

        let subscription_state = SubscriptionState::new();

        let session_state = Arc::new(RwLock::new(SessionState::new(
            ignore_clock_skew,
            secure_channel,
            subscription_state,
        )));

        let message_queue = Arc::new(RwLock::new(MessageQueue::new()));

        Session {
            application_description,
            session_name,
            session_info,
            session_state,
            certificate_store,
            session_retry_policy: Arc::new(Mutex::new(session_retry_policy)),
            message_queue,
        }
    }

    fn reset(&mut self) {
        // Clear the existing secure channel state
        self.session_state
            .write()
            .secure_channel
            .clear_security_token();
    }

    /// Connects to the server, creates and activates a session. If there
    /// is a failure, it will be communicated by the status code in the result.
    pub async fn connect_and_activate(&mut self) -> Result<(), StatusCode> {
        // Connect now using the session state
        self.connect().await?;
        self.create_session()?;
        self.activate_session()?;
        Ok(())
    }

    /// Sets the session retry policy that dictates what this session will do if the connection
    /// fails or goes down. The retry policy enables the session to retry a connection on an
    /// interval up to a maxmimum number of times.
    pub fn set_session_retry_policy(&mut self, session_retry_policy: SessionRetryPolicy) {
        self.session_retry_policy = Arc::new(Mutex::new(session_retry_policy));
    }

    /// Register a callback to be notified when the session has been closed.
    pub fn set_session_closed_callback<CB>(&mut self, session_closed_callback: CB)
    where
        CB: OnSessionClosed + Send + Sync + 'static,
    {
        let mut session_state = self.session_state.write();
        session_state.set_session_closed_callback(session_closed_callback);
    }

    /// Registers a callback to be notified when the session connection status has changed.
    /// This will be called if connection status changes from connected to disconnected or vice versa.
    pub fn set_connection_status_callback<CB>(&mut self, connection_status_callback: CB)
    where
        CB: OnConnectionStatusChange + Send + Sync + 'static,
    {
        let mut session_state = self.session_state.write();
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
    pub async fn reconnect_and_activate(&mut self) -> Result<(), StatusCode> {
        // Do nothing if already connected / activated
        if self.is_connected() {
            session_error!(
                self,
                "Reconnect is going to do nothing because already connected"
            );
            return Err(StatusCode::BadUnexpectedError);
        } else {
            // Reset the session state
            self.reset();

            // Connect to server (again)
            self.connect_no_retry().await?;

            // Attempt to reactivate the existing session
            match self.activate_session() {
                Err(status_code) => {
                    // Activation didn't work, so create a new session
                    info!("Session activation failed on reconnect, error = {}, so creating a new session", status_code);
                    {
                        let mut session_state = self.session_state.write();
                        session_state.reset(&mut self.message_queue.write());
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
        let subscription_ids = self
            .session_state
            .read()
            .subscription_state
            .subscription_ids();

        // Start by getting the subscription ids
        if let Some(subscription_ids) = subscription_ids {
            // Try to use TransferSubscriptions to move subscriptions_ids over. If this
            // works then there is nothing else to do.
            let mut subscription_ids_to_recreate =
                subscription_ids.iter().copied().collect::<HashSet<u32>>();
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
            subscription_ids_to_recreate
                .iter()
                .for_each(|subscription_id| {
                    log::info!("Recreating subscription {subscription_id}");
                    // Remove the subscription data, create it again from scratch
                    let deleted_subscription = self.session_state.write().subscription_state.delete_subscription(*subscription_id);

                    let Some(subscription) = deleted_subscription else {
                        panic!("Subscription {subscription_id}, doesn't exist although it should");
                    };

                    // Attempt to replicate the subscription (subscription id will be new)
                    if let Ok(subscription_id) = self.create_subscription_inner(
                        subscription.publishing_interval(),
                        subscription.lifetime_count(),
                        subscription.max_keep_alive_count(),
                        subscription.max_notifications_per_publish(),
                        subscription.priority(),
                        subscription.publishing_enabled(),
                        subscription.notification_callback(),
                    ) {
                        log::info!("New subscription created with id {}", subscription_id);

                        // For each monitored item
                        let items_to_create = subscription
                            .monitored_items()
                            .iter()
                            .map(|(_, item)| MonitoredItemCreateRequest {
                                item_to_monitor: item.item_to_monitor().clone(),
                                monitoring_mode: item.monitoring_mode(),
                                requested_parameters: MonitoringParameters {
                                    client_handle: item.client_handle(),
                                    sampling_interval: item.sampling_interval(),
                                    filter: ExtensionObject::null(),
                                    queue_size: item.queue_size() as u32,
                                    discard_oldest: true,
                                },
                            })
                            .collect::<Vec<MonitoredItemCreateRequest>>();
                        let _ = self.create_monitored_items(
                            subscription_id,
                            TimestampsToReturn::Both,
                            &items_to_create,
                        );

                        // Recreate any triggers for the monitored item. This code assumes monitored item
                        // ids are the same value as they were in the previous subscription.
                        subscription.monitored_items().iter().for_each(|(_, item)| {
                            let triggered_items = item.triggered_items();
                            if !triggered_items.is_empty() {
                                let links_to_add =
                                    triggered_items.iter().copied().collect::<Vec<u32>>();
                                let _ = self.set_triggering(
                                    subscription_id,
                                    item.id(),
                                    links_to_add.as_slice(),
                                    &[],
                                );
                            }
                        });
                    } else {
                        session_warn!(self, "Could not create a subscription from the existing subscription {subscription_id}");
                    }
                });
        }
        Ok(())
    }

    /// Connects to the server using the retry policy to repeat connecting until such time as it
    /// succeeds or the policy says to give up. If there is a failure, it will be
    /// communicated by the status code in the result.
    pub async fn connect(&mut self) -> Result<(), StatusCode> {
        log::debug!("Connect");
        loop {
            let Err(status_code) = self.connect_no_retry().await else {
                log::info!("Connect was successful");
                let mut session_retry_policy = self.session_retry_policy.lock();
                session_retry_policy.reset_retry_count();
                return Ok(());
            };

            self.disconnect().await;
            let mut session_retry_policy = self.session_retry_policy.lock();
            session_retry_policy.increment_retry_count();
            session_warn!(
                self,
                "Connect was unsuccessful, error = {status_code}, retries = {}",
                session_retry_policy.retry_count()
            );

            match session_retry_policy.should_retry_connect(DateTime::now()) {
                Answer::GiveUp => {
                    session_error!(
                        self,
                        "Session has given up trying to connect to the server after {} retries",
                        session_retry_policy.retry_count()
                    );
                    return Err(StatusCode::BadNotConnected);
                }
                Answer::Retry => {
                    info!("Retrying to connect to server...");
                    session_retry_policy.set_last_attempt(DateTime::now());
                }
                Answer::WaitFor(sleep_for) => {
                    // Sleep for the instructed interval before looping around and trying
                    // once more.
                    tokio::time::sleep(Duration::from_millis(sleep_for as u64)).await;
                }
            }
        }
    }

    /// Connects to the server using the configured session arguments. No attempt is made to retry
    /// the connection if the attempt fails. If there is a failure, it will be communicated by the
    /// status code in the result.
    pub async fn connect_no_retry(&mut self) -> Result<(), StatusCode> {
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();
        log::info!("Connect");
        let security_policy =
            SecurityPolicy::from_str(self.session_info.endpoint.security_policy_uri.as_ref())
                .unwrap();
        if security_policy == SecurityPolicy::Unknown {
            session_error!(
                self,
                "connect, security policy \"{}\" is unknown",
                self.session_info.endpoint.security_policy_uri.as_ref()
            );
            return Err(StatusCode::BadSecurityPolicyRejected);
        }
        let (cert, key) = { self.certificate_store.read_own_cert_and_pkey_optional() };

        {
            self.session_state.write().secure_channel.private_key = key;
            self.session_state.write().secure_channel.cert = cert;
            self.session_state.write().secure_channel.security_policy = security_policy;
            self.session_state.write().secure_channel.security_mode =
                self.session_info.endpoint.security_mode;
            let _ = self
                .session_state
                .write()
                .secure_channel
                .set_remote_cert_from_byte_string(&self.session_info.endpoint.server_certificate);
            log::info!("Security policy = {security_policy:?}");
            log::info!(
                "Security mode = {:?}",
                self.session_info.endpoint.security_mode
            );
        }

        crate::tcp_transport::connect(
            endpoint_url.as_ref(),
            self.session_state.clone(),
            self.message_queue.clone(),
            &self.session_state.read().connection_state,
        )
        .await?;
        self.open_secure_channel()?;
        self.on_connection_status_change(true);
        Ok(())
    }

    pub(crate) fn session_state(&self) -> Arc<RwLock<SessionState>> {
        self.session_state.clone()
    }

    /// Disconnect from the server. Disconnect is an explicit command to drop the socket and throw
    /// away all state information. If you disconnect you cannot reconnect to your existing session
    /// or retrieve any existing subscriptions.
    pub async fn disconnect(&mut self) {
        log::debug!("Disconnect");
        if self.is_connected() {
            let _ = self.close_session_and_delete_subscriptions();
            let _ = self.close_secure_channel();
            self.message_queue.read().quit();
            crate::tcp_transport::wait_for_disconnect(&self.session_state.read().connection_state)
                .await;
            self.on_connection_status_change(false);
        }
    }

    /// Test if the session is in a connected state
    pub fn is_connected(&self) -> bool {
        self.session_state.read().connection_state.is_connected()
    }

    /// Polls on the session which basically dispatches any pending
    /// async responses, attempts to reconnect if the client is disconnected from the client and
    /// sleeps a little bit if nothing needed to be done.
    pub async fn poll(&mut self) -> Result<bool, ()> {
        if self.is_connected() {
            let mut session_state = self.session_state.write();
            return Ok(session_state.handle_publish_responses(&mut self.message_queue.write()));
        }
        let should_retry_connect = {
            let session_retry_policy = self.session_retry_policy.lock();
            session_retry_policy.should_retry_connect(DateTime::now())
        };
        match should_retry_connect {
            Answer::GiveUp => {
                let session_retry_policy = self.session_retry_policy.lock();
                session_error!(
                    self,
                    "Session has given up trying to reconnect to the server after {} retries",
                    session_retry_policy.retry_count()
                );
                Err(())
            }
            Answer::Retry => {
                info!("Retrying to reconnect to server...");
                {
                    let mut session_retry_policy = self.session_retry_policy.lock();
                    session_retry_policy.set_last_attempt(DateTime::now());
                }
                if self.reconnect_and_activate().await.is_ok() {
                    info!("Retry to connect was successful");
                    let mut session_retry_policy = self.session_retry_policy.lock();
                    session_retry_policy.reset_retry_count();
                } else {
                    let mut session_retry_policy = self.session_retry_policy.lock();
                    session_retry_policy.increment_retry_count();
                    session_warn!(
                        self,
                        "Reconnect was unsuccessful, retries = {}",
                        session_retry_policy.retry_count()
                    );
                    drop(session_retry_policy);
                    self.disconnect().await;
                }
                Ok(true)
            }
            Answer::WaitFor(_) => {
                // Note we could sleep for the interval in the WaitFor(), but the poll() sleeps
                // anyway so it probably makes no odds.
                Ok(false)
            }
        }
    }

    /// This is the internal handler for create subscription that receives the callback wrapped up and reference counted.
    fn create_subscription_inner(
        &self,
        publishing_interval: f64,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
        publishing_enabled: bool,
        callback: Arc<Mutex<dyn OnSubscriptionNotification + Send + Sync + 'static>>,
    ) -> Result<u32, StatusCode> {
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
            process_service_result(&response.response_header)?;
            let subscription = Subscription::new(
                response.subscription_id,
                response.revised_publishing_interval,
                response.revised_lifetime_count,
                response.revised_max_keep_alive_count,
                max_notifications_per_publish,
                publishing_enabled,
                priority,
                callback,
            );

            self.session_state
                .write()
                .subscription_state
                .add_subscription(subscription);

            // Send an async publish request for this new subscription
            {
                let mut session_state = self.session_state.write();
                let _ = session_state.async_publish(&mut self.message_queue.write());
            }

            session_debug!(
                self,
                "create_subscription, created a subscription with id {}",
                response.subscription_id
            );
            Ok(response.subscription_id)
        } else {
            session_error!(self, "create_subscription failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }

    /// Deletes all subscriptions by sending a [`DeleteSubscriptionsRequest`] to the server with
    /// ids for all subscriptions.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<(u32, StatusCode)>)` - List of (id, status code) result for delete action on each id, `Good` or `BadSubscriptionIdInvalid`
    pub fn delete_all_subscriptions(&self) -> Result<Vec<(u32, StatusCode)>, StatusCode> {
        let subscription_ids = {
            self.session_state
                .read()
                .subscription_state
                .subscription_ids()
        };
        if let Some(ref subscription_ids) = subscription_ids {
            let status_codes = self.delete_subscriptions(subscription_ids.as_slice())?;
            // Return a list of (id, status_code) for each subscription
            Ok(subscription_ids
                .iter()
                .zip(status_codes)
                .map(|(id, status_code)| (*id, status_code))
                .collect())
        } else {
            // No subscriptions
            session_trace!(
                self,
                "delete_all_subscriptions, called when there are no subscriptions"
            );
            Err(StatusCode::BadNothingToDo)
        }
    }

    /// Closes the session and deletes all subscriptions
    pub fn close_session_and_delete_subscriptions(&self) -> Result<(), StatusCode> {
        if !self.is_connected() {
            return Err(StatusCode::BadNotConnected);
        }
        // for some operations like enumerating endpoints, there is no session equivalent
        // on the server and it's a local helper object, only. In that case: nothing to do.
        if self.session_state.read().session_id().identifier == Identifier::Numeric(0) {
            return Ok(());
        }
        let request = CloseSessionRequest {
            delete_subscriptions: true,
            request_header: self.make_request_header(),
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::CloseSessionResponse(_) = response {
            if let Some(subscription_ids) = self
                .session_state
                .read()
                .subscription_state
                .subscription_ids()
            {
                for subscription_id in subscription_ids {
                    self.session_state
                        .write()
                        .subscription_state
                        .delete_subscription(subscription_id);
                }
            }
            Ok(())
        } else {
            session_error!(self, "close_session failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }

    /// Returns a string identifier for the session
    pub(crate) fn session_id(&self) -> String {
        format!("session:{}", self.session_state().read().id())
    }

    /// Notify any callback of the connection status change
    fn on_connection_status_change(&self, connected: bool) {
        self.session_state
            .write()
            .on_connection_status_change(connected);
    }

    /// Returns the security policy
    fn security_policy(&self) -> SecurityPolicy {
        self.session_state.read().secure_channel.security_policy
    }

    // Test if the subscription by id exists
    fn subscription_exists(&self, subscription_id: u32) -> bool {
        self.session_state
            .read()
            .subscription_state
            .subscription_exists(subscription_id)
    }

    // Creates a user identity token according to the endpoint, policy that the client is currently connected to the
    // server with.
    fn user_identity_token(
        &self,
        server_cert: &Option<X509>,
        server_nonce: &[u8],
    ) -> Result<(ExtensionObject, SignatureData), StatusCode> {
        let user_identity_token = &self.session_info.user_identity_token;
        let user_token_type = match user_identity_token {
            IdentityToken::Anonymous => UserTokenType::Anonymous,
            IdentityToken::UserName(_, _) => UserTokenType::UserName,
            IdentityToken::X509(_, _) => UserTokenType::Certificate,
        };

        let endpoint = &self.session_info.endpoint;
        let policy = endpoint.find_policy(user_token_type);
        session_debug!(self, "Endpoint policy = {:?}", policy);

        // Return the result
        let Some(policy) = policy else {
            session_error!(
                self,
                "Cannot find user token type {:?} for this endpoint, cannot connect",
                user_token_type
            );
            return Err(StatusCode::BadSecurityPolicyRejected);
        };

        let security_policy = if policy.security_policy_uri.is_null() {
            // Assume None
            SecurityPolicy::None
        } else {
            SecurityPolicy::from_uri(policy.security_policy_uri.as_ref())
        };
        if security_policy == SecurityPolicy::Unknown {
            session_error!(
                self,
                "Can't support the security policy {}",
                policy.security_policy_uri
            );
            return Err(StatusCode::BadSecurityPolicyRejected);
        }

        match user_identity_token {
            IdentityToken::Anonymous => {
                let identity_token = AnonymousIdentityToken {
                    policy_id: policy.policy_id.clone(),
                };
                let identity_token = ExtensionObject::from_encodable(
                    ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary,
                    &identity_token,
                );
                Ok((identity_token, SignatureData::null()))
            }
            IdentityToken::UserName(ref user, ref pass) => {
                let identity_token = self.make_user_name_identity_token(
                    &self.session_state.read().secure_channel,
                    policy,
                    user,
                    pass,
                )?;
                let identity_token = ExtensionObject::from_encodable(
                    ObjectId::UserNameIdentityToken_Encoding_DefaultBinary,
                    &identity_token,
                );
                Ok((identity_token, SignatureData::null()))
            }
            IdentityToken::X509(ref cert_path, ref private_key_path) => {
                let Some(ref server_cert) = server_cert else {
                    session_error!(self, "Cannot create an X509IdentityToken because the remote server has no cert with which to create a signature");
                    return Err(StatusCode::BadCertificateInvalid);
                };
                // The cert will be supplied to the server along with a signature to prove we have the private key to go with the cert
                let certificate_data = CertificateStore::read_cert(cert_path).map_err(|e| {
                    session_error!(
                        self,
                        "Certificate cannot be loaded from path {}, error = {}",
                        cert_path.to_str().unwrap(),
                        e
                    );
                    StatusCode::BadSecurityPolicyRejected
                })?;
                let private_key = CertificateStore::read_pkey(private_key_path).map_err(|e| {
                    session_error!(
                        self,
                        "Private key cannot be loaded from path {}, error = {}",
                        private_key_path.to_str().unwrap(),
                        e
                    );
                    StatusCode::BadSecurityPolicyRejected
                })?;

                // Create a signature using the X509 private key to sign the server's cert and nonce
                let user_token_signature = crypto::create_signature_data(
                    &private_key,
                    security_policy,
                    &server_cert.as_byte_string(),
                    &ByteString::from(server_nonce),
                )?;

                // Create identity token
                let identity_token = X509IdentityToken {
                    policy_id: policy.policy_id.clone(),
                    certificate_data: certificate_data.as_byte_string(),
                };
                let identity_token = ExtensionObject::from_encodable(
                    ObjectId::X509IdentityToken_Encoding_DefaultBinary,
                    &identity_token,
                );

                Ok((identity_token, user_token_signature))
            }
        }
    }

    /// Create a filled in UserNameIdentityToken by using the endpoint's token policy, the current
    /// secure channel information and the user name and password.
    fn make_user_name_identity_token(
        &self,
        secure_channel: &SecureChannel,
        user_token_policy: &UserTokenPolicy,
        user: &str,
        pass: &str,
    ) -> Result<UserNameIdentityToken, StatusCode> {
        let channel_security_policy = secure_channel.security_policy;
        let nonce = secure_channel.remote_nonce();
        let cert = &secure_channel.remote_cert;
        make_user_name_identity_token(
            channel_security_policy,
            user_token_policy,
            nonce,
            &cert,
            user,
            pass,
        )
    }
}

/// Start a task that will periodically "ping" the server to keep the session alive. The ping rate
/// will be 3/4 the session timeout rate.
///
/// NOTE: This code assumes that the session_timeout period never changes, e.g. if you
/// connected to a server, negotiate a timeout period and then for whatever reason need to
/// reconnect to that same server, you will receive the same timeout. If you get a different
/// timeout then this code will not care and will continue to ping at the original rate.
async fn session_activity_task(
    session_timeout: f64,
    session_state: Arc<RwLock<SessionState>>,
    message_queue: Arc<RwLock<MessageQueue>>,
) {
    log::debug!("spawn_session_activity_task({session_timeout})");

    let connection_state = session_state.read().connection_state();

    // Session activity will happen every 3/4 of the timeout period
    const MIN_SESSION_ACTIVITY_MS: u64 = 1000;
    let session_activity = cmp::max((session_timeout as u64 / 4) * 3, MIN_SESSION_ACTIVITY_MS);
    log::debug!("session timeout is {session_timeout}, activity timer is {session_activity}");

    // The timer runs at a higher frequency timer loop to terminate as soon after the session
    // state has terminated. Each time it runs it will test if the interval has elapsed or not.
    let session_activity_interval = Duration::from_millis(session_activity);
    let mut timer = interval(Duration::from_millis(MIN_SESSION_ACTIVITY_MS));
    let mut last_timeout = Instant::now();

    loop {
        timer.tick().await;

        if connection_state.is_finished() {
            log::info!("Session activity timer is terminating");
            break;
        }

        // Get the time now
        let now = Instant::now();

        // Calculate to interval since last check
        let interval = now - last_timeout;
        if interval > session_activity_interval {
            match connection_state.state() {
                ConnectionState::Processing => {
                    log::info!("Session activity keep-alive request");
                    let mut session_state = session_state.write();
                    let request_header = session_state.make_request_header();
                    let request = ReadRequest {
                        request_header,
                        max_age: 1f64,
                        timestamps_to_return: TimestampsToReturn::Server,
                        nodes_to_read: Some(vec![]),
                    };
                    // The response to this is ignored
                    let _ =
                        session_state.async_send_request(request, None, &mut message_queue.write());
                }
                connection_state => {
                    info!(
                        "Session activity keep-alive is doing nothing - connection state = {:?}",
                        connection_state
                    );
                }
            };
            last_timeout = now;
        }
    }

    info!("Session activity timer task is finished");
}

/// Start a task that will periodically send a publish request to keep the subscriptions alive.
/// The request rate will be 3/4 of the shortest (revised publishing interval * the revised keep
/// alive count) of all subscriptions that belong to a single session.
async fn subscription_activity_task(
    session_state: Arc<RwLock<SessionState>>,
    message_queue: Arc<RwLock<MessageQueue>>,
) {
    log::debug!("spawn_subscription_activity_task");

    let connection_state = session_state.read().connection_state();

    const MIN_SUBSCRIPTION_ACTIVITY_MS: u64 = 1000;

    // The timer runs at a higher frequency timer loop to terminate as soon after the session
    // state has terminated. Each time it runs it will test if the interval has elapsed or not.
    let mut timer = interval(Duration::from_millis(MIN_SUBSCRIPTION_ACTIVITY_MS));

    let mut last_timeout: Instant;
    let mut subscription_activity_interval: Duration;

    loop {
        timer.tick().await;

        if connection_state.is_finished() {
            info!("Session activity timer is terminating");
            break;
        }

        if let (Some(keep_alive_timeout), last_publish_request) = {
            (
                session_state.read().subscription_state.keep_alive_timeout(),
                session_state
                    .read()
                    .subscription_state
                    .last_publish_request(),
            )
        } {
            subscription_activity_interval = Duration::from_millis((keep_alive_timeout / 4) * 3);
            last_timeout = last_publish_request;

            // Get the time now
            let now = Instant::now();

            // Calculate to interval since last check
            let interval = now - last_timeout;
            if interval > subscription_activity_interval {
                let mut session_state = session_state.write();
                let _ = session_state.async_publish(&mut message_queue.write());
            }
        }
    }

    info!("Subscription activity timer task is finished");
}

/// Internal constant for the sleep interval used during polling
const POLL_SLEEP_INTERVAL: Duration = Duration::from_millis(10);

/// Synchronously runs a polling loop over the supplied session. Running a session performs
/// periodic actions such as receiving messages, processing subscriptions, and recovering from
/// connection errors. The run function will return if the session is disconnected and
/// cannot be reestablished.
pub async fn run(session: Arc<RwLock<Session>>) {
    let (_tx, rx) = oneshot::channel();
    session_task(session, POLL_SLEEP_INTERVAL, rx).await
}

impl Service for Session {
    /// Construct a request header for the session. All requests after create session are expected
    /// to supply an authentication token.
    fn make_request_header(&self) -> RequestHeader {
        self.session_state.write().make_request_header()
    }

    /// Synchronously sends a request. The return value is the response to the request
    fn send_request<T>(&self, request: T) -> Result<SupportedMessage, StatusCode>
    where
        T: Into<SupportedMessage>,
    {
        log::debug!("Send request");
        self.session_state
            .write()
            .send_request(request, &mut self.message_queue.write())
    }

    // Asynchronously sends a request. The return value is the request handle of the request
    fn async_send_request<T>(
        &self,
        request: T,
        sender: Option<SyncSender<SupportedMessage>>,
    ) -> Result<u32, StatusCode>
    where
        T: Into<SupportedMessage>,
    {
        let mut session_state = self.session_state.write();
        session_state.async_send_request(request, sender, &mut self.message_queue.write())
    }
}

impl DiscoveryService for Session {
    fn find_servers<T>(&self, endpoint_url: T) -> Result<Vec<ApplicationDescription>, StatusCode>
    where
        T: Into<UAString>,
    {
        let request = FindServersRequest {
            request_header: self.make_request_header(),
            endpoint_url: endpoint_url.into(),
            locale_ids: None,
            server_uris: None,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::FindServersResponse(response) = response {
            process_service_result(&response.response_header)?;
            let servers = if let Some(servers) = response.servers {
                servers
            } else {
                Vec::new()
            };
            Ok(servers)
        } else {
            Err(process_unexpected_response(response))
        }
    }

    fn get_endpoints(&self) -> Result<Vec<EndpointDescription>, StatusCode> {
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
            process_service_result(&response.response_header)?;
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
            Err(process_unexpected_response(response))
        }
    }

    fn register_server(&self, server: RegisteredServer) -> Result<(), StatusCode> {
        let request = RegisterServerRequest {
            request_header: self.make_request_header(),
            server,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::RegisterServerResponse(response) = response {
            process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(process_unexpected_response(response))
        }
    }
}

impl SecureChannelService for Session {
    fn open_secure_channel(&self) -> Result<(), StatusCode> {
        session_debug!(self, "open_secure_channel");
        let mut session_state = self.session_state.write();
        session_state.issue_or_renew_secure_channel(
            SecurityTokenRequestType::Issue,
            &mut self.message_queue.write(),
        )
    }

    fn close_secure_channel(&self) -> Result<(), StatusCode> {
        let request = CloseSecureChannelRequest {
            request_header: self.make_request_header(),
        };
        // We do not wait for a response because there may not be one. Just return
        let _ = self.async_send_request(request, None);
        Ok(())
    }
}

impl SessionService for Session {
    fn create_session(&self) -> Result<NodeId, StatusCode> {
        // Get some state stuff
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();

        let client_nonce = {
            let secure_channel = &self.session_state.read().secure_channel;
            secure_channel.local_nonce_as_byte_string()
        };

        let server_uri = UAString::null();
        let session_name = self.session_name.clone();

        let (client_certificate, _) = self.certificate_store.read_own_cert_and_pkey_optional();

        // Security
        let client_certificate = if let Some(ref client_certificate) = client_certificate {
            client_certificate.as_byte_string()
        } else {
            ByteString::null()
        };

        // Requested session timeout should be larger than your expected subscription rate.
        let requested_session_timeout = {
            let session_retry_policy = self.session_retry_policy.lock();
            session_retry_policy.session_timeout()
        };

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
        let SupportedMessage::CreateSessionResponse(response) = response else {
            return Err(process_unexpected_response(response));
        };
        process_service_result(&response.response_header)?;

        let session_id = {
            let mut session_state = self.session_state.write();
            session_state.set_session_id(response.session_id.clone());
            session_state.set_authentication_token(response.authentication_token.clone());
            {
                let secure_channel = &mut self.session_state.write().secure_channel;
                let _ = secure_channel.set_remote_nonce_from_byte_string(&response.server_nonce);
                let _ =
                    secure_channel.set_remote_cert_from_byte_string(&response.server_certificate);
            }
            // When ignoring clock skew, we calculate the time offset between the client
            // and the server and use that to compensate for the difference in time.
            if self.session_state.read().ignore_clock_skew
                && !response.response_header.timestamp.is_null()
            {
                let offset = response.response_header.timestamp - DateTime::now();
                // Update the client offset by adding the new offset.
                session_state.set_client_offset(offset.to_std().unwrap());
            }
            session_state.session_id()
        };

        // session_debug!(self, "Server nonce is {:?}", response.server_nonce);

        // The server certificate is validated if the policy requires it
        let security_policy = self.security_policy();
        let cert_status_code = if security_policy != SecurityPolicy::None {
            if let Ok(server_certificate) =
                crypto::X509::from_byte_string(&response.server_certificate)
            {
                // Validate server certificate against hostname and application_uri
                let hostname = hostname_from_url(self.session_info.endpoint.endpoint_url.as_ref())
                    .map_err(|_| StatusCode::BadUnexpectedError)?;
                let application_uri = self.session_info.endpoint.server.application_uri.as_ref();

                let result = self
                    .certificate_store
                    .validate_or_reject_application_instance_cert(
                        &server_certificate,
                        security_policy,
                        Some(&hostname),
                        Some(application_uri),
                    );
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
            return Err(cert_status_code);
        }
        // Spawn a task to ping the server to keep the connection alive before the session
        // timeout period.
        session_debug!(
            self,
            "Revised session timeout is {}",
            response.revised_session_timeout
        );
        tokio::spawn(session_activity_task(
            response.revised_session_timeout,
            self.session_state.clone(),
            self.message_queue.clone(),
        ));
        tokio::spawn(subscription_activity_task(
            self.session_state.clone(),
            self.message_queue.clone(),
        ));

        // TODO Verify signature using server's public key (from endpoint) comparing with data made from client certificate and nonce.
        // crypto::verify_signature_data(verification_key, security_policy, server_certificate, client_certificate, client_nonce);
        Ok(session_id)
    }

    fn activate_session(&self) -> Result<(), StatusCode> {
        let (user_identity_token, user_token_signature) = {
            let secure_channel = &self.session_state.read().secure_channel;
            self.user_identity_token(&secure_channel.remote_cert, secure_channel.remote_nonce())?
        };

        let locale_ids = if self.session_info.preferred_locales.is_empty() {
            None
        } else {
            let locale_ids = self
                .session_info
                .preferred_locales
                .iter()
                .map(UAString::from)
                .collect();
            Some(locale_ids)
        };

        let security_policy = self.security_policy();
        let client_signature = match security_policy {
            SecurityPolicy::None => SignatureData::null(),
            _ => {
                let secure_channel = &self.session_state.read().secure_channel;
                let server_cert = &secure_channel.remote_cert;
                let server_nonce = secure_channel.remote_nonce();

                let (_, client_pkey) = self.certificate_store.read_own_cert_and_pkey_optional();

                // Create a signature data
                if client_pkey.is_none() {
                    session_error!(self, "Cannot create client signature - no pkey!");
                    return Err(StatusCode::BadUnexpectedError);
                } else if server_cert.is_none() {
                    session_error!(
                        self,
                        "Cannot sign server certificate because server cert is null"
                    );
                    return Err(StatusCode::BadUnexpectedError);
                } else if server_nonce.is_empty() {
                    session_error!(
                        self,
                        "Cannot sign server certificate because server nonce is empty"
                    );
                    return Err(StatusCode::BadUnexpectedError);
                }

                let server_cert = secure_channel
                    .remote_cert
                    .as_ref()
                    .unwrap()
                    .as_byte_string();
                let server_nonce = ByteString::from(secure_channel.remote_nonce());
                let signing_key = client_pkey.as_ref().unwrap();
                crypto::create_signature_data(
                    signing_key,
                    security_policy,
                    &server_cert,
                    &server_nonce,
                )?
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
            process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(process_unexpected_response(response))
        }
    }

    fn cancel(&self, request_handle: IntegerId) -> Result<u32, StatusCode> {
        let request = CancelRequest {
            request_header: self.make_request_header(),
            request_handle,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::CancelResponse(response) = response {
            process_service_result(&response.response_header)?;
            Ok(response.cancel_count)
        } else {
            Err(process_unexpected_response(response))
        }
    }
}

impl SubscriptionService for Session {
    fn create_subscription<CB>(
        &self,
        publishing_interval: f64,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
        publishing_enabled: bool,
        callback: CB,
    ) -> Result<u32, StatusCode>
    where
        CB: OnSubscriptionNotification + Send + Sync + 'static,
    {
        self.create_subscription_inner(
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            priority,
            publishing_enabled,
            Arc::new(Mutex::new(callback)),
        )
    }

    fn modify_subscription(
        &self,
        subscription_id: u32,
        publishing_interval: f64,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
    ) -> Result<(), StatusCode> {
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
                process_service_result(&response.response_header)?;
                self.session_state
                    .write()
                    .subscription_state
                    .modify_subscription(
                        subscription_id,
                        response.revised_publishing_interval,
                        response.revised_lifetime_count,
                        response.revised_max_keep_alive_count,
                        max_notifications_per_publish,
                        priority,
                    );
                session_debug!(self, "modify_subscription success for {}", subscription_id);
                Ok(())
            } else {
                session_error!(self, "modify_subscription failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn set_publishing_mode(
        &self,
        subscription_ids: &[u32],
        publishing_enabled: bool,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        session_debug!(
            self,
            "set_publishing_mode, for subscriptions {:?}, publishing enabled {}",
            subscription_ids,
            publishing_enabled
        );
        if subscription_ids.is_empty() {
            // No subscriptions
            session_error!(
                self,
                "set_publishing_mode, no subscription ids were provided"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = SetPublishingModeRequest {
                request_header: self.make_request_header(),
                publishing_enabled,
                subscription_ids: Some(subscription_ids.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::SetPublishingModeResponse(response) = response {
                process_service_result(&response.response_header)?;
                {
                    // Clear out all subscriptions, assuming the delete worked
                    self.session_state
                        .write()
                        .subscription_state
                        .set_publishing_mode(subscription_ids, publishing_enabled);
                }
                session_debug!(self, "set_publishing_mode success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "set_publishing_mode failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn transfer_subscriptions(
        &self,
        subscription_ids: &[u32],
        send_initial_values: bool,
    ) -> Result<Vec<TransferResult>, StatusCode> {
        if subscription_ids.is_empty() {
            // No subscriptions
            session_error!(
                self,
                "set_publishing_mode, no subscription ids were provided"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = TransferSubscriptionsRequest {
                request_header: self.make_request_header(),
                subscription_ids: Some(subscription_ids.to_vec()),
                send_initial_values,
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::TransferSubscriptionsResponse(response) = response {
                process_service_result(&response.response_header)?;
                session_debug!(self, "transfer_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "transfer_subscriptions failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn delete_subscription(&self, subscription_id: u32) -> Result<StatusCode, StatusCode> {
        if subscription_id == 0 {
            session_error!(self, "delete_subscription, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "delete_subscription, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else {
            let result = self.delete_subscriptions(&[subscription_id][..])?;
            Ok(result[0])
        }
    }

    fn delete_subscriptions(
        &self,
        subscription_ids: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
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
                process_service_result(&response.response_header)?;
                {
                    // Clear out deleted subscriptions, assuming the delete worked
                    subscription_ids.iter().for_each(|id| {
                        let _ = self
                            .session_state
                            .write()
                            .subscription_state
                            .delete_subscription(*id);
                    });
                }
                session_debug!(self, "delete_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "delete_subscriptions failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }
}

impl NodeManagementService for Session {
    fn add_nodes(&self, nodes_to_add: &[AddNodesItem]) -> Result<Vec<AddNodesResult>, StatusCode> {
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
                Err(process_unexpected_response(response))
            }
        }
    }

    fn add_references(
        &self,
        references_to_add: &[AddReferencesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
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
                Err(process_unexpected_response(response))
            }
        }
    }

    fn delete_nodes(
        &self,
        nodes_to_delete: &[DeleteNodesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
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
                Err(process_unexpected_response(response))
            }
        }
    }

    fn delete_references(
        &self,
        references_to_delete: &[DeleteReferencesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if references_to_delete.is_empty() {
            session_error!(
                self,
                "delete_references, called with no references to delete"
            );
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
                Err(process_unexpected_response(response))
            }
        }
    }
}

impl MonitoredItemService for Session {
    fn create_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: TimestampsToReturn,
        items_to_create: &[MonitoredItemCreateRequest],
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        session_debug!(
            self,
            "create_monitored_items, for subscription {}, {} items",
            subscription_id,
            items_to_create.len()
        );
        if subscription_id == 0 {
            session_error!(self, "create_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "create_monitored_items, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_create.is_empty() {
            session_error!(
                self,
                "create_monitored_items, called with no items to create"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            // Assign each item a unique client handle
            let mut items_to_create = items_to_create.to_vec();
            {
                let mut session_state = self.session_state.write();
                items_to_create.iter_mut().for_each(|i| {
                    //if user doesn't specify a valid client_handle
                    if i.requested_parameters.client_handle == 0 {
                        i.requested_parameters.client_handle =
                            session_state.next_monitored_item_handle();
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
                process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    session_debug!(
                        self,
                        "create_monitored_items, {} items created",
                        items_to_create.len()
                    );
                    // Set the items in our internal state
                    let items_to_create = items_to_create
                        .iter()
                        .zip(results)
                        .map(|(i, r)| subscription::CreateMonitoredItem {
                            id: r.monitored_item_id,
                            client_handle: i.requested_parameters.client_handle,
                            discard_oldest: i.requested_parameters.discard_oldest,
                            item_to_monitor: i.item_to_monitor.clone(),
                            monitoring_mode: i.monitoring_mode,
                            queue_size: r.revised_queue_size,
                            sampling_interval: r.revised_sampling_interval,
                        })
                        .collect::<Vec<subscription::CreateMonitoredItem>>();
                    {
                        self.session_state
                            .write()
                            .subscription_state
                            .insert_monitored_items(subscription_id, &items_to_create);
                    }
                } else {
                    session_debug!(
                        self,
                        "create_monitored_items, success but no monitored items were created"
                    );
                }
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "create_monitored_items failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn modify_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: TimestampsToReturn,
        items_to_modify: &[MonitoredItemModifyRequest],
    ) -> Result<Vec<MonitoredItemModifyResult>, StatusCode> {
        session_debug!(
            self,
            "modify_monitored_items, for subscription {}, {} items",
            subscription_id,
            items_to_modify.len()
        );
        if subscription_id == 0 {
            session_error!(self, "modify_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "modify_monitored_items, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_modify.is_empty() {
            session_error!(
                self,
                "modify_monitored_items, called with no items to modify"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let monitored_item_ids = items_to_modify
                .iter()
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
                process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    // Set the items in our internal state
                    let items_to_modify = monitored_item_ids
                        .iter()
                        .zip(results.iter())
                        .map(|(id, r)| subscription::ModifyMonitoredItem {
                            id: *id,
                            queue_size: r.revised_queue_size,
                            sampling_interval: r.revised_sampling_interval,
                        })
                        .collect::<Vec<subscription::ModifyMonitoredItem>>();
                    {
                        self.session_state
                            .write()
                            .subscription_state
                            .modify_monitored_items(subscription_id, &items_to_modify);
                    }
                }
                session_debug!(self, "modify_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "modify_monitored_items failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn set_monitoring_mode(
        &self,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        monitored_item_ids: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
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
                Err(process_unexpected_response(response))
            }
        }
    }

    fn set_triggering(
        &self,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: &[u32],
        links_to_remove: &[u32],
    ) -> Result<(Option<Vec<StatusCode>>, Option<Vec<StatusCode>>), StatusCode> {
        if links_to_add.is_empty() && links_to_remove.is_empty() {
            session_error!(self, "set_triggering, called with nothing to add or remove");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = {
                let links_to_add = if links_to_add.is_empty() {
                    None
                } else {
                    Some(links_to_add.to_vec())
                };
                let links_to_remove = if links_to_remove.is_empty() {
                    None
                } else {
                    Some(links_to_remove.to_vec())
                };
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
                self.session_state
                    .write()
                    .subscription_state
                    .set_triggering(
                        subscription_id,
                        triggering_item_id,
                        links_to_add,
                        links_to_remove,
                    );
                Ok((response.add_results, response.remove_results))
            } else {
                session_error!(self, "set_triggering failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn delete_monitored_items(
        &self,
        subscription_id: u32,
        items_to_delete: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        session_debug!(
            self,
            "delete_monitored_items, subscription {} for {} items",
            subscription_id,
            items_to_delete.len()
        );
        if subscription_id == 0 {
            session_error!(self, "delete_monitored_items, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "delete_monitored_items, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else if items_to_delete.is_empty() {
            session_error!(
                self,
                "delete_monitored_items, called with no items to delete"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = DeleteMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                monitored_item_ids: Some(items_to_delete.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::DeleteMonitoredItemsResponse(response) = response {
                process_service_result(&response.response_header)?;
                if response.results.is_some() {
                    self.session_state
                        .write()
                        .subscription_state
                        .delete_monitored_items(subscription_id, items_to_delete);
                }
                session_debug!(self, "delete_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                session_error!(self, "delete_monitored_items failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }
}

impl ViewService for Session {
    fn browse(
        &self,
        nodes_to_browse: &[BrowseDescription],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if nodes_to_browse.is_empty() {
            session_error!(self, "browse, was not supplied with any nodes to browse");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = BrowseRequest {
                request_header: self.make_request_header(),
                view: ViewDescription {
                    view_id: NodeId::null(),
                    timestamp: DateTime::null(),
                    view_version: 0,
                },
                requested_max_references_per_node: 1000,
                nodes_to_browse: Some(nodes_to_browse.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::BrowseResponse(response) = response {
                session_debug!(self, "browse, success");
                process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                session_error!(self, "browse failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn browse_next(
        &self,
        release_continuation_points: bool,
        continuation_points: &[ByteString],
    ) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if continuation_points.is_empty() {
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
                process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                session_error!(self, "browse_next failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn translate_browse_paths_to_node_ids(
        &self,
        browse_paths: &[BrowsePath],
    ) -> Result<Vec<BrowsePathResult>, StatusCode> {
        if browse_paths.is_empty() {
            session_error!(
                self,
                "translate_browse_paths_to_node_ids, was not supplied with any browse paths"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = TranslateBrowsePathsToNodeIdsRequest {
                request_header: self.make_request_header(),
                browse_paths: Some(browse_paths.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::TranslateBrowsePathsToNodeIdsResponse(response) = response {
                session_debug!(self, "translate_browse_paths_to_node_ids, success");
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap_or_default())
            } else {
                session_error!(
                    self,
                    "translate_browse_paths_to_node_ids failed {:?}",
                    response
                );
                Err(process_unexpected_response(response))
            }
        }
    }

    fn register_nodes(&self, nodes_to_register: &[NodeId]) -> Result<Vec<NodeId>, StatusCode> {
        if nodes_to_register.is_empty() {
            session_error!(
                self,
                "register_nodes, was not supplied with any nodes to register"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = RegisterNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_register: Some(nodes_to_register.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::RegisterNodesResponse(response) = response {
                session_debug!(self, "register_nodes, success");
                process_service_result(&response.response_header)?;
                Ok(response.registered_node_ids.unwrap())
            } else {
                session_error!(self, "register_nodes failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn unregister_nodes(&self, nodes_to_unregister: &[NodeId]) -> Result<(), StatusCode> {
        if nodes_to_unregister.is_empty() {
            session_error!(
                self,
                "unregister_nodes, was not supplied with any nodes to unregister"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = UnregisterNodesRequest {
                request_header: self.make_request_header(),
                nodes_to_unregister: Some(nodes_to_unregister.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::UnregisterNodesResponse(response) = response {
                session_debug!(self, "unregister_nodes, success");
                process_service_result(&response.response_header)?;
                Ok(())
            } else {
                session_error!(self, "unregister_nodes failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }
}

impl MethodService for Session {
    fn call<T>(&self, method: T) -> Result<CallMethodResult, StatusCode>
    where
        T: Into<CallMethodRequest>,
    {
        session_debug!(self, "call()");
        let methods_to_call = Some(vec![method.into()]);
        let request = CallRequest {
            request_header: self.make_request_header(),
            methods_to_call,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::CallResponse(response) = response {
            if let Some(mut results) = response.results {
                if results.len() != 1 {
                    session_error!(
                        self,
                        "call(), expecting a result from the call to the server, got {} results",
                        results.len()
                    );
                    Err(StatusCode::BadUnexpectedError)
                } else {
                    Ok(results.remove(0))
                }
            } else {
                session_error!(
                    self,
                    "call(), expecting a result from the call to the server, got nothing"
                );
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            Err(process_unexpected_response(response))
        }
    }
}

impl AttributeService for Session {
    fn read(
        &self,
        nodes_to_read: &[ReadValueId],
        timestamps_to_return: TimestampsToReturn,
        max_age: f64,
    ) -> Result<Vec<DataValue>, StatusCode> {
        if nodes_to_read.is_empty() {
            // No subscriptions
            session_error!(self, "read(), was not supplied with any nodes to read");
            Err(StatusCode::BadNothingToDo)
        } else {
            session_debug!(self, "read() requested to read nodes {:?}", nodes_to_read);
            let request = ReadRequest {
                request_header: self.make_request_header(),
                max_age,
                timestamps_to_return,
                nodes_to_read: Some(nodes_to_read.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::ReadResponse(response) = response {
                session_debug!(self, "read(), success");
                process_service_result(&response.response_header)?;
                let results = if let Some(results) = response.results {
                    results
                } else {
                    Vec::new()
                };
                Ok(results)
            } else {
                session_error!(self, "read() value failed");
                Err(process_unexpected_response(response))
            }
        }
    }

    fn history_read(
        &self,
        history_read_details: HistoryReadAction,
        timestamps_to_return: TimestampsToReturn,
        release_continuation_points: bool,
        nodes_to_read: &[HistoryReadValueId],
    ) -> Result<Vec<HistoryReadResult>, StatusCode> {
        // Turn the enum into an extension object
        let history_read_details = ExtensionObject::from(history_read_details);
        let request = HistoryReadRequest {
            request_header: self.make_request_header(),
            history_read_details,
            timestamps_to_return,
            release_continuation_points,
            nodes_to_read: if nodes_to_read.is_empty() {
                None
            } else {
                Some(nodes_to_read.to_vec())
            },
        };
        session_debug!(
            self,
            "history_read() requested to read nodes {:?}",
            nodes_to_read
        );
        let response = self.send_request(request)?;
        if let SupportedMessage::HistoryReadResponse(response) = response {
            session_debug!(self, "history_read(), success");
            process_service_result(&response.response_header)?;
            let results = if let Some(results) = response.results {
                results
            } else {
                Vec::new()
            };
            Ok(results)
        } else {
            session_error!(self, "history_read() value failed");
            Err(process_unexpected_response(response))
        }
    }

    fn write(&self, nodes_to_write: &[WriteValue]) -> Result<Vec<StatusCode>, StatusCode> {
        if nodes_to_write.is_empty() {
            // No subscriptions
            session_error!(self, "write() was not supplied with any nodes to write");
            Err(StatusCode::BadNothingToDo)
        } else {
            let request = WriteRequest {
                request_header: self.make_request_header(),
                nodes_to_write: Some(nodes_to_write.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::WriteResponse(response) = response {
                session_debug!(self, "write(), success");
                process_service_result(&response.response_header)?;
                Ok(response.results.unwrap_or_default())
            } else {
                session_error!(self, "write() failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }

    fn history_update(
        &self,
        history_update_details: &[HistoryUpdateAction],
    ) -> Result<Vec<HistoryUpdateResult>, StatusCode> {
        if history_update_details.is_empty() {
            // No subscriptions
            session_error!(
                self,
                "history_update(), was not supplied with any detail to update"
            );
            Err(StatusCode::BadNothingToDo)
        } else {
            // Turn the enums into ExtensionObjects
            let history_update_details = history_update_details
                .iter()
                .map(ExtensionObject::from)
                .collect::<Vec<ExtensionObject>>();

            let request = HistoryUpdateRequest {
                request_header: self.make_request_header(),
                history_update_details: Some(history_update_details.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::HistoryUpdateResponse(response) = response {
                session_debug!(self, "history_update(), success");
                process_service_result(&response.response_header)?;
                let results = if let Some(results) = response.results {
                    results
                } else {
                    Vec::new()
                };
                Ok(results)
            } else {
                session_error!(self, "history_update() failed {:?}", response);
                Err(process_unexpected_response(response))
            }
        }
    }
}

/// The asynchronous main session loop. This is the function that processes responses and
/// keeps the session alive. Note that while the client normally calls `run()` or `run_loop()`
/// to invoke this, there may be situations where the client wishes to directly use this
/// function, for example if the client has its own Tokio runtime and prefers to spawn the task
/// with that.
pub async fn session_task(
    session: Arc<RwLock<Session>>,
    sleep_interval: Duration,
    rx: oneshot::Receiver<SessionCommand>,
) {
    log::debug!("Run session main loop");
    tokio::select! {
        _ = async {
            let mut timer = interval(sleep_interval);
            loop {
                // Poll the session.
                let poll_result = {
                    let mut session = session.write();
                    session.poll().await
                };
                match poll_result {
                    Ok(did_something) => {
                        // If the session did nothing, then sleep for a moment to save some CPU
                        if !did_something {
                            timer.tick().await;
                        }
                    }
                    Err(_) => {
                        // Break the loop if connection goes down
                        info!("Run session connection to server broke, so terminating");
                        break;
                    }
                }
            }
        } => {}
        message = rx => {
            if let Ok(message) = message {
                // Only message is a Quit command so no point even testing what it is.
                info!("Run session was terminated by a message {:?}", message);
            }
            else {
                warn!("Run session was terminated, presumably by caller dropping oneshot sender. Don't do that unless you meant to.");
            }
        }
    }
}
