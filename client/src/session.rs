use std::result::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::str::FromStr;

use opcua_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::*;
use opcua_types::node_ids::ObjectId;
use opcua_core::crypto;
use opcua_core::crypto::{SecurityPolicy, CertificateStore, X509, PKey};

use client;
use comms::tcp_transport::TcpTransport;
use subscription::{Subscription, MonitoredItem};
use subscription_state::SubscriptionState;

/// Information about the server endpoint, security policy, security mode and user identity that the session will
/// will use to establish a connection.
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
    pub client_pkey: Option<PKey>,
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

const DEFAULT_SESSION_TIMEOUT: u32 = 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT: u32 = 10 * 1000;
const SEND_BUFFER_SIZE: usize = 65536;
const RECEIVE_BUFFER_SIZE: usize = 65536;
const MAX_BUFFER_SIZE: usize = 65536;

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
    /// The next handle to assign to a request
    pub last_request_handle: UInt32,
    /// The authentication token negotiated with the server (if any)
    pub authentication_token: NodeId,
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            send_buffer_size: SEND_BUFFER_SIZE,
            receive_buffer_size: RECEIVE_BUFFER_SIZE,
            max_message_size: MAX_BUFFER_SIZE,
            last_request_handle: 1,
            authentication_token: NodeId::null(),
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
    session_state: Arc<Mutex<SessionState>>,
    /// Subscriptions state
    pub subscription_state: SubscriptionState,
    /// Next monitored item handle
    last_monitored_item_handle: UInt32,
    /// Transport layer
    transport: TcpTransport,
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.is_connected() {
            self.disconnect();
        }
    }
}

impl Session {
    /// Create a new session.
    pub fn new(application_description: ApplicationDescription, certificate_store: Arc<Mutex<CertificateStore>>, session_info: SessionInfo) -> Session {
        let session_state = Arc::new(Mutex::new(SessionState::new()));
        let transport = TcpTransport::new(certificate_store, session_state.clone());
        let subscription_state = SubscriptionState::new();
        Session {
            application_description,
            session_info,
            session_state,
            subscription_state,
            transport,
            last_monitored_item_handle: 0,
        }
    }

    /// Connects to the server (if possible) using the configured session arguments
    pub fn connect(&mut self) -> Result<(), StatusCode> {
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();

        let security_policy = SecurityPolicy::from_str(self.session_info.endpoint.security_policy_uri.as_ref()).unwrap();
        if security_policy == SecurityPolicy::Unknown {
            Err(BadSecurityPolicyRejected)
        } else {
            {
                let secure_channel = &mut self.transport.secure_channel;
                secure_channel.set_security_policy(security_policy);
                secure_channel.set_security_mode(self.session_info.endpoint.security_mode);
            }

            let _ = self.transport.connect(endpoint_url.as_ref())?;
            let _ = self.transport.hello(endpoint_url.as_ref())?;
            let _ = self.open_secure_channel()?;
            Ok(())
        }
    }

    /// Connects to the server, creates and activates a session
    pub fn connect_and_activate_session(&mut self) -> Result<(), StatusCode> {
        // Reconnect now using the session state
        let _ = self.connect();
        let _ = self.create_session()?;
        let _ = self.activate_session()?;
        Ok(())
    }

    /// Disconnect from the server
    pub fn disconnect(&mut self) {
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
        let _ = self.async_send_request(SupportedMessage::CloseSecureChannelRequest(request));
        Ok(())
    }

    /// Sends a CreateSession request to the server
    pub fn create_session(&mut self) -> Result<(), StatusCode> {
        // Get some state stuff
        let endpoint_url = UAString::from(self.session_info.endpoint.endpoint_url.clone());

        let client_nonce = self.transport.secure_channel.local_nonce_as_byte_string();

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
        let response = self.send_request(SupportedMessage::CreateSessionRequest(request))?;
        if let SupportedMessage::CreateSessionResponse(response) = response {
            Self::process_service_result(&response.response_header)?;

            let session_state = self.session_state.clone();
            let mut session_state = session_state.lock().unwrap();

            session_state.authentication_token = response.authentication_token;
            let _ = self.transport.secure_channel.set_remote_nonce_from_byte_string(&response.server_nonce);
            let _ = self.transport.secure_channel.set_remote_cert_from_byte_string(&response.server_certificate);
            debug!("server nonce is {:?}", response.server_nonce);

            // TODO Verify signature using server's public key (from endpoint) comparing with
            // data made from client certificate and nonce.

            // crypto::verify_signature_data(verification_key, security_policy, server_certificate, client_certificate, client_nonce);

            // TODO validate server certificate against endpoint

            Ok(())
        } else {
            Err(Self::process_unexpected_response(response))
        }
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

        let security_policy = self.transport.secure_channel.security_policy();
        let client_signature = match security_policy {
            SecurityPolicy::None => SignatureData::null(),
            _ => {
                let server_nonce = self.transport.secure_channel.remote_nonce_as_byte_string();
                let server_cert = self.transport.secure_channel.remote_cert_as_byte_string();
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

        let response = self.send_request(SupportedMessage::ActivateSessionRequest(request))?;
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
        let response = self.send_request(SupportedMessage::FindServersRequest(request))?;
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

    /// Sends a GetEndpoints request to the server
    pub fn get_endpoints(&mut self) -> Result<Vec<EndpointDescription>, StatusCode> {
        debug!("Fetching end points...");
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();
        let request = GetEndpointsRequest {
            request_header: self.make_request_header(),
            endpoint_url,
            locale_ids: None,
            profile_uris: None,
        };

        let response = self.send_request(SupportedMessage::GetEndpointsRequest(request))?;
        if let SupportedMessage::GetEndpointsResponse(response) = response {
            Self::process_service_result(&response.response_header)?;
            if response.endpoints.is_none() {
                Ok(Vec::new())
            } else {
                Ok(response.endpoints.unwrap())
            }
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    /// Sends a BrowseRequest to the server
    pub fn browse(&mut self, nodes_to_browse: &[BrowseDescription]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if nodes_to_browse.is_empty() {
            error!("Cannot browse without any nodes to browse");
            Err(BadInvalidArgument)
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
            let response = self.send_request(SupportedMessage::BrowseRequest(request))?;
            if let SupportedMessage::BrowseResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Sends a BrowseNextRequest to the server
    pub fn browse_next(&mut self, release_continuation_points: bool, continuation_points: &[ByteString]) -> Result<Option<Vec<BrowseResult>>, StatusCode> {
        if continuation_points.is_empty() {
            error!("Cannot browse next without any continuation points");
            Err(BadInvalidArgument)
        } else {
            let request = BrowseNextRequest {
                request_header: self.make_request_header(),
                continuation_points: Some(continuation_points.to_vec()),
                release_continuation_points,
            };
            let response = self.send_request(SupportedMessage::BrowseNextRequest(request))?;
            if let SupportedMessage::BrowseNextResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                Ok(response.results)
            } else {
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Sends a ReadRequest to the server
    pub fn read_nodes(&mut self, nodes_to_read: &[ReadValueId]) -> Result<Option<Vec<DataValue>>, StatusCode> {
        debug!("read_nodes requested to read nodes {:?}", nodes_to_read);
        let request = ReadRequest {
            request_header: self.make_request_header(),
            max_age: 1f64,
            timestamps_to_return: TimestampsToReturn::Server,
            nodes_to_read: Some(nodes_to_read.to_vec()),
        };
        trace!("ReadRequest = {:#?}", request);
        let response = self.send_request(SupportedMessage::ReadRequest(request))?;
        if let SupportedMessage::ReadResponse(response) = response {
            trace!("ReadResponse = {:#?}", response);
            Self::process_service_result(&response.response_header)?;
            Ok(response.results)
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    /// Sends a WriteRequest to the server
    pub fn write_value(&mut self, nodes_to_write: &[WriteValue]) -> Result<Option<Vec<StatusCode>>, StatusCode> {
        let request = WriteRequest {
            request_header: self.make_request_header(),
            nodes_to_write: Some(nodes_to_write.to_vec()),
        };
        let response = self.send_request(SupportedMessage::WriteRequest(request))?;
        if let SupportedMessage::WriteResponse(response) = response {
            Self::process_service_result(&response.response_header)?;
            Ok(response.results)
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    /// Sends a CreateSubscriptionRequest request to the server. A subscription is described by the
    /// supplied subscription struct. The initial values imply the requested interval, lifetime 
    /// and keepalive and the value returned in the response are the revised values. The
    /// subscription id is also returned in the response.
    pub fn create_subscription(&mut self, publishing_interval: Double, lifetime_count: UInt32, max_keep_alive_count: UInt32, max_notifications_per_publish: UInt32, priority: Byte, publishing_enabled: Boolean) -> Result<UInt32, StatusCode> {
        let request = CreateSubscriptionRequest {
            request_header: self.make_request_header(),
            requested_publishing_interval: publishing_interval,
            requested_lifetime_count: lifetime_count,
            requested_max_keep_alive_count: max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
        };
        let response = self.send_request(SupportedMessage::CreateSubscriptionRequest(request))?;
        if let SupportedMessage::CreateSubscriptionResponse(response) = response {
            Self::process_service_result(&response.response_header)?;

            let subscription_id = response.subscription_id;
            let subscription = Subscription {
                subscription_id,
                publishing_interval: response.revised_publishing_interval,
                lifetime_count: response.revised_lifetime_count,
                max_keep_alive_count: response.revised_max_keep_alive_count,
                max_notifications_per_publish,
                publishing_enabled,
                priority,
                change_callback: None,
                monitored_items: HashMap::new(),
            };
            self.subscription_state.subscriptions.insert(subscription_id, subscription);

            Ok(subscription_id)
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    // modify subscription
    pub fn modify_subscription(&mut self, subscription_id: UInt32, publishing_interval: Double, lifetime_count: UInt32, max_keep_alive_count: UInt32, max_notifications_per_publish: UInt32, priority: Byte) -> Result<(), StatusCode> {
        if subscription_id == 0 {
            error!("Subscription id must be non-zero, or the subscription is considered invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_state.subscriptions.contains_key(&subscription_id) {
            error!("Subscription id does not exist");
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
            let response = self.send_request(SupportedMessage::ModifySubscriptionRequest(request))?;
            if let SupportedMessage::ModifySubscriptionResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                if let Some(ref mut subscription) = self.subscription_state.subscriptions.get_mut(&subscription_id) {
                    subscription.publishing_interval = response.revised_publishing_interval;
                    subscription.lifetime_count = response.revised_lifetime_count;
                    subscription.max_keep_alive_count = response.revised_max_keep_alive_count;
                }
                Ok(())
            } else {
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Removes a subscription using its subscription id
    pub fn delete_subscription(&mut self, subscription_id: UInt32) -> Result<DeleteSubscriptionsResponse, StatusCode> {
        if subscription_id == 0 {
            error!("Subscription id must be non-zero, or the subscription is considered invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_state.subscriptions.contains_key(&subscription_id) {
            error!("Subscription id does not exist");
            Err(BadInvalidArgument)
        } else {
            let request = DeleteSubscriptionsRequest {
                request_header: self.make_request_header(),
                subscription_ids: Some(vec![subscription_id]),
            };
            let response = self.send_request(SupportedMessage::DeleteSubscriptionsRequest(request))?;
            if let SupportedMessage::DeleteSubscriptionsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                self.subscription_state.subscriptions.remove(&subscription_id);
                Ok(response)
            } else {
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Create monitored items request
    pub fn create_monitored_items(&mut self, subscription_id: UInt32, mut items_to_create: Vec<MonitoredItemCreateRequest>) -> Result<CreateMonitoredItemsResponse, StatusCode> {
        if subscription_id == 0 {
            error!("Subscription id must be non-zero, or the subscription is considered invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_state.subscriptions.contains_key(&subscription_id) {
            error!("Subscription id does not exist");
            Err(BadInvalidArgument)
        } else if items_to_create.is_empty() {
            error!("Nothing to do!");
            Err(BadNothingToDo)
        } else {
            // Assign each item a unique client handle
            items_to_create.iter_mut().for_each(|i| {
                self.last_monitored_item_handle += 1;
                i.requested_parameters.client_handle = self.last_monitored_item_handle;
            });
            let request = CreateMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                timestamps_to_return: TimestampsToReturn::Both,
                items_to_create: Some(items_to_create.clone()),
            };
            let response = self.send_request(SupportedMessage::CreateMonitoredItemsRequest(request))?;
            if let SupportedMessage::CreateMonitoredItemsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    if let Some(ref mut subscription) = self.subscription_state.subscriptions.get_mut(&subscription_id) {
                        items_to_create.iter().zip(results).for_each(|(i, r)| {
                            let mut monitored_item = MonitoredItem::new(i.requested_parameters.client_handle);
                            monitored_item.set_id(r.monitored_item_id);
                            monitored_item.set_sampling_interval(r.revised_sampling_interval);
                            monitored_item.set_queue_size(r.revised_queue_size);
                            subscription.monitored_items.insert(monitored_item.id(), monitored_item);
                        });
                    }
                }
                Ok(response)
            } else {
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Modifies monitored items in the subscription
    pub fn modify_monitored_items(&mut self, subscription_id: UInt32, items_to_modify: Vec<MonitoredItemModifyRequest>) -> Result<ModifyMonitoredItemsResponse, StatusCode> {
        if subscription_id == 0 {
            error!("Subscription id must be non-zero, or the subscription is considered invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_state.subscriptions.contains_key(&subscription_id) {
            error!("Subscription id does not exist");
            Err(BadInvalidArgument)
        } else {
            let monitored_item_ids: Vec<UInt32> = items_to_modify.iter().map(|i| i.monitored_item_id).collect();


            let request = ModifyMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                timestamps_to_return: TimestampsToReturn::Both,
                items_to_modify: Some(items_to_modify),
            };
            let response = self.send_request(SupportedMessage::ModifyMonitoredItemsRequest(request))?;
            if let SupportedMessage::ModifyMonitoredItemsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                if let Some(ref results) = response.results {
                    if let Some(ref mut subscription) = self.subscription_state.subscriptions.get_mut(&subscription_id) {
                        // Update the monitored items with the revised info from the server
                        monitored_item_ids.iter().zip(results.iter()).for_each(|(monitored_item_id, r)| {
                            if let Some(ref mut monitored_item) = subscription.monitored_items.get_mut(&monitored_item_id) {
                                monitored_item.set_sampling_interval(r.revised_sampling_interval);
                                monitored_item.set_queue_size(r.revised_queue_size);
                            }
                        });
                    }
                }
                Ok(response)
            } else {
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    /// Deletes monitored items from the subscription
    pub fn delete_monitored_items(&mut self, subscription_id: UInt32, monitored_item_ids: Vec<UInt32>) -> Result<DeleteMonitoredItemsResponse, StatusCode> {
        if subscription_id == 0 {
            error!("Subscription id must be non-zero, or the subscription is considered invalid");
            Err(BadInvalidArgument)
        } else if !self.subscription_state.subscriptions.contains_key(&subscription_id) {
            error!("Subscription id does not exist");
            Err(BadInvalidArgument)
        } else {
            let request = DeleteMonitoredItemsRequest {
                request_header: self.make_request_header(),
                subscription_id,
                monitored_item_ids: Some(monitored_item_ids.clone()),
            };
            let response = self.send_request(SupportedMessage::DeleteMonitoredItemsRequest(request))?;
            if let SupportedMessage::DeleteMonitoredItemsResponse(response) = response {
                Self::process_service_result(&response.response_header)?;
                if let Some(_) = response.results {
                    if let Some(ref mut subscription) = self.subscription_state.subscriptions.get_mut(&subscription_id) {
                        // Remove monitored items
                        monitored_item_ids.iter().for_each(|monitored_item_id| {
                            subscription.monitored_items.remove(&monitored_item_id);
                        });
                    }
                }
                Ok(response)
            } else {
                Err(Self::process_unexpected_response(response))
            }
        }
    }

    // Sends a publish request containing any acknowledgements
    pub fn publish(&mut self, subscription_acknowledgements: Vec<SubscriptionAcknowledgement>) -> Result<PublishResponse, StatusCode> {
        let request = PublishRequest {
            request_header: self.make_request_header(),
            subscription_acknowledgements: if subscription_acknowledgements.is_empty() { None } else { Some(subscription_acknowledgements) },
        };
        let response = self.send_request(SupportedMessage::PublishRequest(request))?;
        if let SupportedMessage::PublishResponse(response) = response {
            Self::process_service_result(&response.response_header)?;
            Ok(response)
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }

    pub fn send_request(&mut self, request: SupportedMessage) -> Result<SupportedMessage, StatusCode> {
        match request {
            SupportedMessage::OpenSecureChannelRequest(_) | SupportedMessage::CloseSecureChannelRequest(_) => {}
            _ => {
                // Make sure secure channel token hasn't expired
                let _ = self.ensure_secure_channel_token();
            }
        }
        // Send the request
        self.transport.send_request(request)
    }

    pub fn async_send_request(&mut self, request: SupportedMessage) -> Result<UInt32, StatusCode> {
        match request {
            SupportedMessage::OpenSecureChannelRequest(_) | SupportedMessage::CloseSecureChannelRequest(_) => {}
            _ => {
                // Make sure secure channel token hasn't expired
                let _ = self.ensure_secure_channel_token();
            }
        }
        // Send the request
        self.transport.async_send_request(request)
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

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

    /// Construct a request header for the session
    fn make_request_header(&mut self) -> RequestHeader {
        let (authentication_token, request_handle, timeout_hint) = {
            let mut session_state = self.session_state.lock().unwrap();
            session_state.last_request_handle += 1;
            (session_state.authentication_token.clone(), session_state.last_request_handle, session_state.request_timeout)
        };
        let request_header = RequestHeader {
            authentication_token,
            timestamp: DateTime::now(),
            request_handle,
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint,
            additional_header: ExtensionObject::null(),
        };
        request_header
    }

    fn issue_or_renew_secure_channel(&mut self, request_type: SecurityTokenRequestType) -> Result<(), StatusCode> {
        const REQUESTED_LIFETIME: UInt32 = 60000; // TODO

        let client_nonce = ByteString::nonce();
        self.transport.secure_channel.set_local_nonce(client_nonce.as_ref());

        let security_mode = self.transport.secure_channel.security_mode();
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
            self.transport.set_security_token(response.security_token);
            Ok(())
        } else {
            Err(Self::process_unexpected_response(response))
        }
    }
}