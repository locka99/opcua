//! Session functionality for the current connection including async
//! wrappers around client side requests to server.

use std::result::Result;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use chrono;

use opcua_core::crypto;
use opcua_core::crypto::{CertificateStore, PrivateKey, SecurityPolicy, X509};
use opcua_types::*;
use opcua_types::node_ids::{ObjectId, MethodId};
use opcua_types::service_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;

use client;
use comms::tcp_transport::TcpTransport;
use subscription;
use subscription::{DataChangeCallback, Subscription};
use subscription_state::SubscriptionState;
use session_state::SessionState;

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

/// A session of the client. The session is associated with an endpoint and
/// maintains a state when it is active.
pub struct Session {
    /// The client application's name
    application_description: ApplicationDescription,
    /// The session connection info
    session_info: SessionInfo,
    /// Runtime state of the session, reset if disconnected
    session_state: Arc<RwLock<SessionState>>,
    /// Subscriptions state
    subscription_state: Arc<RwLock<SubscriptionState>>,
    /// Transport layer
    transport: TcpTransport,
    /// Certificate store
    certificate_store: Arc<RwLock<CertificateStore>>,
}

impl Drop for Session {
    fn drop(&mut self) {

// This panics in local discovery server call from server registration
//        if self.is_connected() {
//            self.disconnect();
//        }
    }
}

impl Session {
    /// Create a new session from the supplied application description, certificate store and session
    /// information.
    pub fn new(application_description: ApplicationDescription, certificate_store: Arc<RwLock<CertificateStore>>, session_info: SessionInfo) -> Session {
        let session_state = Arc::new(RwLock::new(SessionState::new()));
        let transport = TcpTransport::new(certificate_store.clone(), session_state.clone());
        let subscription_state = Arc::new(RwLock::new(SubscriptionState::new()));
        Session {
            application_description,
            session_info,
            session_state,
            certificate_store,
            subscription_state,
            transport,
        }
    }

    /// Connects to the server, creates and activates a session. If there
    /// is a failure, it will be communicated by the status code in the result.
    pub fn connect_and_activate_session(&mut self) -> Result<(), StatusCode> {
        // Reconnect now using the session state
        self.connect()?;
        self.create_session()?;
        self.activate_session()?;
        Ok(())
    }

    /// Reconnects to the server and tries to activate the existing session. If there
    /// is a failure, it will be communicated by the status code in the result.
    pub fn reconnect_and_activate_session(&mut self) -> Result<(), StatusCode> {
        let have_authentication_token = {
            let mut session_state = trace_read_lock_unwrap!(self.session_state);
            !session_state.authentication_token.is_null()
        };
        // Do nothing if already connected / activated
        if self.is_connected() {
            error!("Reconnect is going to do nothing because already connected");
            Err(StatusCode::BadUnexpectedError)
        } else if !have_authentication_token {
            // Cannot activate a session without an authentication token
            error!("No session was previously created.");
            Err(StatusCode::BadUnexpectedError)
        } else {
            self.connect()?;

            if let Err(error) = self.activate_session() {
                // Perhaps the server went down and lost all its state?
                // In that instance, the fall back here should be:
                //
                // 1) create a new session
                // 2) activate session
                // 3) reconstruct all subscriptions and monitored items from their client side cached values
                // TODO create session, activate and recreate all the subscriptions and monitored items
                Err(error)
            } else {
                Ok(())
            }
        }
    }

    /// Connects to the server (if possible) using the configured session arguments. If there
    /// is a failure, it will be communicated by the status code in the result.
    pub fn connect(&mut self) -> Result<(), StatusCode> {
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();
        info!("Connect");
        let security_policy = SecurityPolicy::from_str(self.session_info.endpoint.security_policy_uri.as_ref()).unwrap();
        if security_policy == SecurityPolicy::Unknown {
            error!("connect, security policy \"{}\" is unknown", self.session_info.endpoint.security_policy_uri.as_ref());
            Err(BadSecurityPolicyRejected)
        } else {
            {
                let mut secure_channel = trace_write_lock_unwrap!( self.transport.secure_channel);
                secure_channel.set_security_policy(security_policy);
                secure_channel.set_security_mode(self.session_info.endpoint.security_mode);
                let _ = secure_channel.set_remote_cert_from_byte_string(&self.session_info.endpoint.server_certificate);
                info!("Security policy = {:?}", security_policy);
                info!("Security mode = {:?}", self.session_info.endpoint.security_mode);
            }

            self.transport.connect(endpoint_url.as_ref())?;
            self.transport.hello(endpoint_url.as_ref())?;
            self.open_secure_channel()?;
            Ok(())
        }
    }

    /// Disconnect from the server. Disconnect
    pub fn disconnect(&mut self) {
        let _ = self.delete_all_subscriptions();
        let _ = self.close_secure_channel();
        self.transport.disconnect();
    }

    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    /// Sends an OpenSecureChannel request to the server
    pub fn open_secure_channel(&mut self) -> Result<(), StatusCode> {
        self.issue_or_renew_secure_channel(SecurityTokenRequestType::Issue)
    }

    /// Sends a CloseSecureChannel request to the server
    pub fn close_secure_channel(&mut self) -> Result<(), StatusCode> {
        let request = CloseSecureChannelRequest {
            request_header: self.make_request_header(),
        };
        // We do not wait for a response because there may not be one. Just return
        let _ = self.async_send_request(request);
        Ok(())
    }

    /// Sends a CreateSession request to the server. Returns the session id of the created session.
    /// Internally, the session will store the authentication token which is used for requests
    /// subsequent to this create session call.
    pub fn create_session(&mut self) -> Result<NodeId, StatusCode> {
        // Get some state stuff
        let endpoint_url = UAString::from(self.session_info.endpoint.endpoint_url.clone());

        let client_nonce = {
            let secure_channel = trace_read_lock_unwrap!( self.transport.secure_channel);
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

        let request = CreateSessionRequest {
            request_header: self.make_request_header(),
            client_description: self.application_description.clone(),
            server_uri,
            endpoint_url,
            session_name,
            client_nonce,
            client_certificate,
            requested_session_timeout: 0f64,
            max_response_message_size: 0,
        };

        debug!("CreateSessionRequest = {:?}", request);

        let response = self.send_request(request)?;
        if let SupportedMessage::CreateSessionResponse(response) = response {
            Self::process_service_result(&response.response_header)?;

            let session_state = self.session_state.clone();
            let mut session_state = trace_write_lock_unwrap!(session_state);

            session_state.set_session_id(response.session_id);
            session_state.authentication_token = response.authentication_token;
            {
                let mut secure_channel = trace_write_lock_unwrap!( self.transport.secure_channel);
                let _ = secure_channel.set_remote_nonce_from_byte_string(&response.server_nonce);
                let _ = secure_channel.set_remote_cert_from_byte_string(&response.server_certificate);
            }
            debug!("server nonce is {:?}", response.server_nonce);

            // The server certificate is validated if the policy requires it
            let security_policy = self.security_policy();
            let cert_status_code = if security_policy != SecurityPolicy::None {
                if let Ok(server_certificate) = crypto::X509::from_byte_string(&response.server_certificate) {
                    // Validate server certificate against hostname and application_uri
                    let hostname = hostname_from_url(self.session_info.endpoint.endpoint_url.as_ref()).map_err(|_| BadUnexpectedError)?;
                    let application_uri = self.session_info.endpoint.server.application_uri.as_ref();

                    let mut certificate_store = trace_write_lock_unwrap!(self.certificate_store);
                    let result = certificate_store.validate_or_reject_application_instance_cert(&server_certificate, Some(&hostname), Some(application_uri));
                    if result.is_bad() {
                        result
                    } else {
                        Good
                    }
                } else {
                    error!("Server did not supply a valid X509 certificate");
                    BadCertificateInvalid
                }
            } else {
                Good
            };

            if !cert_status_code.is_good() {
                error!("Server's certificate was rejected");
                Err(cert_status_code)
            } else {
                // TODO Verify signature using server's public key (from endpoint) comparing with data made from client certificate and nonce.
                // crypto::verify_signature_data(verification_key, security_policy, server_certificate, client_certificate, client_nonce);
                Ok(session_state.session_id())
            }
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    fn security_policy(&self) -> SecurityPolicy {
        let secure_channel = trace_read_lock_unwrap!( self.transport.secure_channel);
        secure_channel.security_policy()
    }

    /// Sends an ActivateSession request to the server
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
                let secure_channel = trace_read_lock_unwrap!(self.transport.secure_channel);
                let server_nonce = secure_channel.remote_nonce_as_byte_string();
                let server_cert = secure_channel.remote_cert_as_byte_string();
                // Create a signature data
                // let session_state = self.session_state.lock().unwrap();
                if self.session_info.client_pkey.is_none() {
                    error!("Cannot create client signature - no pkey!");
                    return Err(BadUnexpectedError);
                } else if server_cert.is_null() {
                    error!("Cannot sign server certificate because server cert is null");
                    return Err(BadUnexpectedError);
                } else if server_nonce.is_null() {
                    error!("Cannot sign server certificate because server nonce is null");
                    return Err(BadUnexpectedError);
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
            Self::process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    // Find a bunch of servers
    pub fn find_servers<T>(&mut self, discovery_url: T) -> Result<Vec<ApplicationDescription>, StatusCode> where T: Into<String> {
        let request = FindServersRequest {
            request_header: self.make_request_header(),
            endpoint_url: UAString::from(discovery_url.into()),
            locale_ids: None,
            server_uris: None,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::FindServersResponse(response) = response {
            Self::process_service_result(&response.response_header)?;
            let servers = if let Some(servers) = response.servers {
                servers
            } else {
                Vec::new()
            };
            Ok(servers)
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    pub fn register_server(&mut self, server: RegisteredServer) -> Result<(), StatusCode> {
        let request = RegisterServerRequest {
            request_header: self.make_request_header(),
            server,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::RegisterServerResponse(response) = response {
            Self::process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(Self::process_unexpected_response(response))
        }
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
            Self::process_service_result(&response.response_header)?;
            if response.endpoints.is_none() {
                debug!("get_endpoints, success but no endpoints");
                Ok(Vec::new())
            } else {
                debug!("get_endpoints, success");
                Ok(response.endpoints.unwrap())
            }
        } else {
            error!("get_endpoints failed {:?}", response);
            Err(Self::process_unexpected_response(response))
        }
    }

    /// Sends a BrowseRequest to the server
    pub fn browse(&mut self, nodes_to_browse: &[BrowseDescription]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if nodes_to_browse.is_empty() {
            error!("browse, was not supplied with any nodes to browse");
            Err(BadNothingToDo)
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
                Self::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                error!("browse failed {:?}", response);
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Sends a BrowseNextRequest to the server
    pub fn browse_next(&mut self, release_continuation_points: bool, continuation_points: &[ByteString]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if continuation_points.is_empty() {
            error!("browse_next, was not supplied with any continuation points");
            Err(BadNothingToDo)
        } else {
            let request = BrowseNextRequest {
                request_header: self.make_request_header(),
                continuation_points: Some(continuation_points.to_vec()),
                release_continuation_points,
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::BrowseNextResponse(response) = response {
                debug!("browse_next, success");
                Self::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                error!("browse_next failed {:?}", response);
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Sends a ReadRequest to the server
    pub fn read_nodes(&mut self, nodes_to_read: &[ReadValueId]) -> Result<Option<Vec<DataValue>>, StatusCode> {
        if nodes_to_read.is_empty() {
            // No subscriptions
            error!("read_nodes, was not supplied with any nodes to read");
            Err(BadNothingToDo)
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
                Self::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                error!("write_value failed {:?}", response);
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Sends a WriteRequest to the server
    pub fn write_value(&mut self, nodes_to_write: &[WriteValue]) -> Result<Option<Vec<StatusCode>>, StatusCode> {
        if nodes_to_write.is_empty() {
            // No subscriptions
            error!("write_value() was not supplied with any nodes to write");
            Err(BadNothingToDo)
        } else {
            let request = WriteRequest {
                request_header: self.make_request_header(),
                nodes_to_write: Some(nodes_to_write.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::WriteResponse(response) = response {
                debug!("write_value, success");
                Self::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                error!("write_value failed {:?}", response);
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Sends a CreateSubscriptionRequest request to the server. A subscription is described by the
    /// supplied subscription struct. The initial values imply the requested interval, lifetime
    /// and keepalive and the value returned in the response are the revised values. The
    /// subscription id is also returned in the response.
    pub fn create_subscription(&mut self, publishing_interval: Double, lifetime_count: UInt32, max_keep_alive_count: UInt32, max_notifications_per_publish: UInt32, priority: Byte, publishing_enabled: Boolean, callback: DataChangeCallback)
                               -> Result<UInt32, StatusCode> {
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
            Self::process_service_result(&response.response_header)?;
            let subscription = Subscription::new(response.subscription_id, response.revised_publishing_interval,
                                                 response.revised_lifetime_count,
                                                 response.revised_max_keep_alive_count,
                                                 max_notifications_per_publish,
                                                 publishing_enabled,
                                                 priority,
                                                 callback);

            {
                let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                subscription_state.add_subscription(subscription);
            }
            debug!("create_subscription, created a subscription with id {}", response.subscription_id);
            Ok(response.subscription_id)
        } else {
            error!("create_subscription failed {:?}", response);
            Err(Self::process_unexpected_response(response))
        }
    }

    // modify subscription
    pub fn modify_subscription(&mut self, subscription_id: UInt32, publishing_interval: Double, lifetime_count: UInt32, max_keep_alive_count: UInt32, max_notifications_per_publish: UInt32, priority: Byte) -> Result<(), StatusCode> {
        if subscription_id == 0 {
            error!("modify_subscription, subscription id must be non-zero, or the subscription is considered invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("modify_subscription, subscription id does not exist");
            Err(BadInvalidArgument)
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
                Self::process_service_result(&response.response_header)?;
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
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Removes a subscription using its subscription id
    pub fn delete_subscription(&mut self, subscription_id: UInt32) -> Result<StatusCode, StatusCode> {
        if subscription_id == 0 {
            error!("delete_subscription, subscription id 0 is invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("delete_subscription, subscription id {} does not exist", subscription_id);
            Err(BadInvalidArgument)
        } else {
            let request = DeleteSubscriptionsRequest {
                request_header: self.make_request_header(),
                subscription_ids: Some(vec![subscription_id]),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::DeleteSubscriptionsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                {
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.delete_subscription(subscription_id);
                }
                debug!("delete_subscription success for {}", subscription_id);
                Ok(response.results.as_ref().unwrap()[0])
            } else {
                error!("delete_subscription failed {:?}", response);
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Removes all subscriptions, assuming there are any to remove
    pub fn delete_all_subscriptions(&mut self) -> Result<Vec<StatusCode>, StatusCode> {
        let subscription_ids = {
            let subscription_state = trace_read_lock_unwrap!(self.subscription_state);
            subscription_state.subscription_ids()
        };
        if subscription_ids.is_none() {
            // No subscriptions
            error!("delete_all_subscriptions, called when there are no subscriptions");
            Err(BadNothingToDo)
        } else {
            // Send a delete request holding all the subscription ides that we wish to delete
            let request = DeleteSubscriptionsRequest {
                request_header: self.make_request_header(),
                subscription_ids,
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::DeleteSubscriptionsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                {
                    // Clear out all subscriptions, assuming the delete worked
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.delete_all_subscriptions();
                }
                debug!("delete_all_subscriptions success");
                Ok(response.results.unwrap())
            } else {
                error!("delete_all_subscriptions failed {:?}", response);
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Sets the publishing mode for one or more subscriptions
    pub fn set_publishing_mode(&mut self, subscription_ids: &[UInt32], publishing_enabled: Boolean) -> Result<Vec<StatusCode>, StatusCode> {
        debug!("set_publishing_mode, for subscriptions {:?}, publishing enabled {}", subscription_ids, publishing_enabled);
        if subscription_ids.is_empty() {
            // No subscriptions
            error!("set_publishing_mode, no subscription ids were provided");
            Err(BadNothingToDo)
        } else {
            let request = SetPublishingModeRequest {
                request_header: self.make_request_header(),
                publishing_enabled,
                subscription_ids: Some(subscription_ids.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::SetPublishingModeResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                {
                    // Clear out all subscriptions, assuming the delete worked
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.set_publishing_mode(subscription_ids, publishing_enabled);
                }
                debug!("set_publishing_mode success");
                Ok(response.results.unwrap())
            } else {
                error!("set_publishing_mode failed {:?}", response);
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Create monitored items request
    pub fn create_monitored_items(&mut self, subscription_id: UInt32, items_to_create: &[MonitoredItemCreateRequest]) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        debug!("create_monitored_items, for subscription {}, {} items", subscription_id, items_to_create.len());
        if subscription_id == 0 {
            error!("create_monitored_items, subscription id 0 is invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("create_monitored_items, subscription id {} does not exist", subscription_id);
            Err(BadInvalidArgument)
        } else if items_to_create.is_empty() {
            error!("create_monitored_items, called with no items to create");
            Err(BadNothingToDo)
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
                timestamps_to_return: TimestampsToReturn::Both,
                items_to_create: Some(items_to_create.clone()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::CreateMonitoredItemsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    debug!("create_monitored_items, {} items created", items_to_create.len());
                    // Set the items in our internal state
                    let items_to_create = items_to_create.iter()
                        .zip(results)
                        .map(|(i, r)| {
                            subscription::CreateMonitoredItem {
                                id: r.monitored_item_id,
                                client_handle: i.requested_parameters.client_handle,
                                item_to_monitor: i.item_to_monitor.clone(),
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
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Modifies monitored items in the subscription
    pub fn modify_monitored_items(&mut self, subscription_id: UInt32, items_to_modify: &[MonitoredItemModifyRequest]) -> Result<Vec<MonitoredItemModifyResult>, StatusCode> {
        debug!("modify_monitored_items, for subscription {}, {} items", subscription_id, items_to_modify.len());
        if subscription_id == 0 {
            error!("modify_monitored_items, subscription id 0 is invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("modify_monitored_items, subscription id {} does not exist", subscription_id);
            Err(BadInvalidArgument)
        } else if items_to_modify.is_empty() {
            error!("modify_monitored_items, called with no items to modify");
            Err(BadNothingToDo)
        } else {
            let monitored_item_ids = items_to_modify.iter()
                .map(|i| i.monitored_item_id)
                .collect::<Vec<UInt32>>();
            let request = ModifyMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                timestamps_to_return: TimestampsToReturn::Both,
                items_to_modify: Some(items_to_modify.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::ModifyMonitoredItemsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
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
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Deletes monitored items from the subscription
    pub fn delete_monitored_items(&mut self, subscription_id: UInt32, items_to_delete: &[UInt32]) -> Result<Vec<StatusCode>, StatusCode> {
        debug!("delete_monitored_items, subscription {} for {} items", subscription_id, items_to_delete.len());
        if subscription_id == 0 {
            error!("delete_monitored_items, subscription id 0 is invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            error!("delete_monitored_items, subscription id {} does not exist", subscription_id);
            Err(BadInvalidArgument)
        } else if items_to_delete.is_empty() {
            error!("delete_monitored_items, called with no items to delete");
            Err(BadNothingToDo)
        } else {
            let request = DeleteMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                monitored_item_ids: Some(items_to_delete.to_vec()),
            };
            let response = self.send_request(request)?;
            if let SupportedMessage::DeleteMonitoredItemsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                if let Some(_) = response.results {
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.delete_monitored_items(subscription_id, items_to_delete);
                }
                debug!("delete_monitored_items, success");
                Ok(response.results.unwrap())
            } else {
                error!("delete_monitored_items failed {:?}", response);
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Calls a single method on an object on the server via a call method request.
    pub fn call_method<T>(&mut self, method: T) -> Result<CallMethodResult, StatusCode> where T: Into<CallMethodRequest> {
        let methods_to_call = Some(vec![method.into()]);
        let request = CallRequest {
            request_header: self.make_request_header(),
            methods_to_call,
        };
        let response = self.send_request(request)?;
        if let SupportedMessage::CallResponse(response) = response {
            if let Some(mut results) = response.results {
                if results.len() != 1 {
                    error!("Expecting a result from the call to the server, got {} results", results.len());
                    Err(BadUnexpectedError)
                } else {
                    Ok(results.remove(0))
                }
            } else {
                error!("Expecting a result from the call to the server, got nothing");
                Err(BadUnexpectedError)
            }
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    /// Calls GetMonitoredItems via call_method(), putting a sane interface on the input / output
    pub fn call_get_monitored_items(&mut self, subscription_id: UInt32) -> Result<(Vec<UInt32>, Vec<UInt32>), StatusCode> {
        let args = Some(vec![Variant::from(subscription_id)]);
        let object_id: NodeId = ObjectId::Server.into();
        let method_id: NodeId = MethodId::Server_GetMonitoredItems.into();
        let request: CallMethodRequest = (object_id, method_id, args).into();
        let response = self.call_method(request)?;
        if let Some(mut result) = response.output_arguments {
            if result.len() == 2 {
                let server_handles = result.remove(0).into_u32_array()?;
                let client_handles = result.remove(0).into_u32_array()?;
                Ok((server_handles, client_handles))
            } else {
                error!("Expected a result with 2 args and didn't get it.");
                Err(BadUnexpectedError)
            }
        } else {
            error!("Expected a result and didn't get it.");
            Err(BadUnexpectedError)
        }
    }

    // Test if the subscription by id exists
    fn subscription_exists(&self, subscription_id: UInt32) -> bool {
        let subscription_state = trace_read_lock_unwrap!(self.subscription_state);
        subscription_state.subscription_exists(subscription_id)
    }

    /// Sends a publish request containing acknowledgements for previous notifications.
    /// TODO this function needs to be refactored as an asynchronous operation.
    fn async_publish(&mut self, subscription_acknowledgements: &[SubscriptionAcknowledgement]) -> Result<UInt32, StatusCode> {
        debug!("async_publish with {} subscription acknowledgements", subscription_acknowledgements.len());
        let request = PublishRequest {
            request_header: self.make_request_header(),
            subscription_acknowledgements: if subscription_acknowledgements.is_empty() { None } else { Some(subscription_acknowledgements.to_vec()) },
        };
        let request_handle = self.async_send_request(request)?;
        debug!("async_publish, request sent with handle {}", request_handle);
        {
            // Store the request handle so a publish response (or error) can be associated with the request later
            let mut session_state = trace_write_lock_unwrap!(self.session_state);
            session_state.pending_requests.insert(request_handle);
        }
        Ok(request_handle)
    }

    /// Synchronously sends a request. The return value is the response to the request
    fn send_request<T>(&mut self, request: T) -> Result<SupportedMessage, StatusCode> where T: Into<SupportedMessage> {
        // Send the request
        let request_handle = self.async_send_request(request)?;
        // Wait for the response
        let request_timeout = {
            let session_state = trace_read_lock_unwrap!(self.session_state);
            session_state.request_timeout
        };
        self.wait_for_response(request_handle, request_timeout)
    }

    /// Asynchronously sends a request. The return value is the request handle of the request
    fn async_send_request<T>(&mut self, request: T) -> Result<UInt32, StatusCode> where T: Into<SupportedMessage> {
        let request = request.into();
        match request {
            SupportedMessage::OpenSecureChannelRequest(_) | SupportedMessage::CloseSecureChannelRequest(_) => {}
            _ => {
                // Make sure secure channel token hasn't expired
                let _ = self.ensure_secure_channel_token();
            }
        }
        // Send the request
        let request_handle = request.request_handle();
        let _ = self.transport.async_send_request(request)?;
        Ok(request_handle)
    }

    /// Asks the session to poll, which basically allows clients who are doing nothing but receiving
    /// notifications to receive them.
    pub fn poll(&mut self) {
        // This is a dirty hack for a blocking TCP stream - if we have any outstanding publish requests
        // then we try to read from the stream otherwise do nothing. Trying to read when there is nothing
        // expected would cause the stream to block forever. Other threads waiting for a
        // lock on this session would hang too. Moving to tokio and non-blocking
        // IO would require a refactor but would probably fix this.
        if self.poll_async_messages().is_err() {
            use std;
            let poll_timeout = 100;
            std::thread::sleep(std::time::Duration::from_millis(poll_timeout as u64));
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    // Process any async messages we expect to receive
    fn poll_async_messages(&mut self) -> Result<(), StatusCode> {
        let request_timeout = 10000; // TODO
        let pending_responses = {
            let session_state = trace_read_lock_unwrap!(self.session_state);
            session_state.pending_requests.len() > 0
        };
        if pending_responses {
            debug!("Waiting for response poll_async_messages");
            let response = self.transport.wait_for_response(true, request_timeout)?;
            let response_request_handle = response.request_handle();
            let is_publish_request = {
                debug!("is publish req test");
                let mut session_state = trace_write_lock_unwrap!(self.session_state);
                session_state.pending_requests.remove(&response_request_handle)
            };
            if is_publish_request {
                debug!("handle response");
                self.handle_publish_response(response);
            } else {
                error!("Received a response from server which does not match any existing request handle {}", response_request_handle);
            }
            Ok(())
        } else {
            debug!("No pending responses so nothing to do");
            Err(BadNothingToDo)
        }
    }

    /// Wait for a response with a matching request handle. If request handle is 0 then no match
    /// is performed and in fact the function is expected to receive no messages except asynchronous
    /// and housekeeping events from the server. A 0 handle will cause the wait to process at most
    /// one async message before returning.
    fn wait_for_response(&mut self, request_handle: UInt32, request_timeout: UInt32) -> Result<SupportedMessage, StatusCode> {
        if request_handle == 0 {
            panic!("Request handle must be non zero");
        }
        // Receive messages until the one expected comes back. Publish responses will be consumed
        // silently.
        let start = chrono::Utc::now();
        loop {
            debug!("wait_for_response");
            // Note that theoretically, there might be one slow response and then another so the timeout
            // period could be exceeded by nearly double in the worst case, e.g. timeout is 10s,
            // first response (not ours) takes 9.9s and then we wait another 9.9s for the message
            // that is ours. Now the timeout was 19.8s. Should we error even though we eventually
            // got the message outside the timeout?
            let response = self.transport.wait_for_response(false, request_timeout)?;
            let response_request_handle = response.request_handle();

            // Compare the handle of the response to the expected handle
            if response_request_handle == request_handle {
                let now = chrono::Utc::now();
                let request_duration = now.signed_duration_since(start);
                return if request_duration.num_milliseconds() >= request_timeout as i64 {
                    info!("Timeout waiting for response from server");
                    Err(BadTimeout)
                } else {
                    // Straight match so return
                    Ok(response)
                };
            } else {
                // Check if it is a pending publish request
                let is_publish_request = {
                    debug!("is publish req test");
                    let mut session_state = trace_write_lock_unwrap!(self.session_state);
                    session_state.pending_requests.remove(&response_request_handle)
                };
                if is_publish_request {
                    debug!("handle response");
                    self.handle_publish_response(response);
                } else {
                    error!("Received a response from server which does not match any existing request handle {}", response_request_handle);
                }
            }
        }
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
            Err(BadSecurityPolicyRejected)
        } else {
            match self.session_info.user_identity_token {
                client::IdentityToken::Anonymous => {
                    let token = AnonymousIdentityToken {
                        policy_id: policy_id.unwrap(),
                    };
                    Ok(ExtensionObject::from_encodable(ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary, token))
                }
                client::IdentityToken::UserName(ref user, ref pass) => {
                    // TODO Check that the security policy is something we can supply
                    let token = UserNameIdentityToken {
                        policy_id: policy_id.unwrap(),
                        user_name: UAString::from(user.as_ref()),
                        password: ByteString::from(pass.as_bytes()),
                        encryption_algorithm: UAString::null(),
                    };
                    Ok(ExtensionObject::from_encodable(ObjectId::UserNameIdentityToken_Encoding_DefaultBinary, token))
                }
            }
        }
    }

    /// Checks if secure channel token needs to be renewed and renews it
    fn ensure_secure_channel_token(&mut self) -> Result<(), StatusCode> {
        if self.transport.should_renew_security_token() {
            self.issue_or_renew_secure_channel(SecurityTokenRequestType::Renew)
        } else {
            Ok(())
        }
    }

    /// Process a call where the response is not the message corresponding to the request
    /// but something else such as a service fault.
    fn process_unexpected_response(response: SupportedMessage) -> StatusCode {
        match response {
            SupportedMessage::ServiceFault(service_fault) => {
                error!("Received a service fault of {:?} for the request", service_fault.response_header.service_result);
                service_fault.response_header.service_result
            }
            _ => {
                error!("Received an unexpected response to the request");
                BadUnknownResponse
            }
        }
    }

    /// Process the service result, i.e. where the request "succeeded" but the response
    /// contains a failure status code.
    fn process_service_result(response_header: &ResponseHeader) -> Result<(), StatusCode> {
        if response_header.service_result.is_bad() {
            info!("Received a bad service result {:?} from the request", response_header.service_result);
            Err(response_header.service_result)
        } else {
            Ok(())
        }
    }

    /// Construct a request header for the session. All requests after create session are expected
    /// to supply an authentication token.
    fn make_request_header(&mut self) -> RequestHeader {
        let mut session_state = trace_write_lock_unwrap!(self.session_state);
        session_state.make_request_header()
    }

    fn issue_or_renew_secure_channel(&mut self, request_type: SecurityTokenRequestType) -> Result<(), StatusCode> {
        trace!("issue_or_renew_secure_channel({:?})", request_type);

        const REQUESTED_LIFETIME: UInt32 = 60000; // TODO

        let (security_mode, security_policy, client_nonce) = {
            let mut secure_channel = trace_write_lock_unwrap!( self.transport.secure_channel);
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
            self.transport.set_security_token(response.security_token);
            if security_policy != SecurityPolicy::None && (security_mode == MessageSecurityMode::Sign || security_mode == MessageSecurityMode::SignAndEncrypt) {
                let mut secure_channel = trace_write_lock_unwrap!( self.transport.secure_channel);
                secure_channel.set_remote_nonce_from_byte_string(&response.server_nonce)?;
                secure_channel.derive_keys();
            }
            Ok(())
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    /// Function that handles subscription
    pub fn subscription_timer(&mut self) {
        error!("Subscription timer inner");
        // Server may have throttled publish requests
        let wait_for_publish_response = {
            let session_state = trace_read_lock_unwrap!(self.session_state);
            session_state.wait_for_publish_response
        };
        let have_subscriptions = {
            let subscription_state = trace_read_lock_unwrap!(self.subscription_state);
            !subscription_state.is_empty()
        };

        debug!("Timer");
        if have_subscriptions && !wait_for_publish_response {
            error!("Subscription timer has subscriptions and is sending a publish");
            let subscription_acknowledgements = {
                let mut session_state = trace_write_lock_unwrap!(self.session_state);
                // Send a publish request with any acknowledgements
                session_state.subscription_acknowledgements()
            };
            let _ = self.async_publish(&subscription_acknowledgements);
        } else {
            error!("Subscription timer is doing nothing {}, {}", have_subscriptions, !wait_for_publish_response);
        }
        debug!("Timer2");
    }

    /// This is the handler for asynchronous publish responses. It maintains the acknowledegements
    /// to be sent and sends the data change notifications to the client for processing.
    fn handle_publish_response(&mut self, response: SupportedMessage) {
        debug!("handle_publish_response");
        let mut wait_for_publish_response = false;
        match response {
            SupportedMessage::PublishResponse(response) => {
                debug!("PublishResponse");
                // Update subscriptions based on response
                // Queue acknowledgements for next request
                let notification_message = response.notification_message;
                let subscription_id = response.subscription_id;

                // Queue an acknowledgement for this request
                {
                    let mut session_state = trace_write_lock_unwrap!(self.session_state);
                    session_state.subscription_acknowledgements.push(SubscriptionAcknowledgement {
                        subscription_id,
                        sequence_number: notification_message.sequence_number,
                    });
                }

                // Process data change notifications
                let data_change_notifications = notification_message.data_change_notifications();
                if !data_change_notifications.is_empty() {
                    let mut subscription_state = trace_write_lock_unwrap!(self.subscription_state);
                    subscription_state.subscription_data_change(subscription_id, &data_change_notifications);
                }
            }
            SupportedMessage::ServiceFault(response) => {
                debug!("ServiceFault {:?}", response);
                // Terminate timer if
                let service_result = response.response_header.service_result;
                match service_result {
                    StatusCode::BadSessionIdInvalid => {
                        //   BadSessionIdInvalid
                        trace!("Subscription timer received BadSessionIdInvalid error code");
                    }
                    StatusCode::BadNoSubscription => {
                        //   BadNoSubscription
                        trace!("Subscription timer received BadNoSubscription error code");
                    }
                    StatusCode::BadTooManyPublishRequests => {
                        //   BadTooManyPublishRequests
                        trace!("Subscription timer received BadTooManyPublishRequests error code");
                        // Turn off publish requests until server says otherwise
                        wait_for_publish_response = false;
                    }
                    _ => {
                        trace!("Subscription timer received error code {:?}", service_result);
                    }
                }
            }
            _ => {
                panic!("Should not be handling non publish responses from here")
            }
        }

        // Turn on/off publish requests
        {
            let mut session_state = trace_write_lock_unwrap!(self.session_state);
            session_state.wait_for_publish_response = wait_for_publish_response;
        }
    }
}