// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides server state information, such as status, configuration, running servers and so on.

use std::sync::Arc;

use crate::core::prelude::*;
use crate::crypto::{user_identity, PrivateKey, SecurityPolicy, X509};
use crate::sync::*;
use crate::types::{
    profiles,
    service_types::{
        ActivateSessionRequest, AnonymousIdentityToken, ApplicationDescription, ApplicationType,
        EndpointDescription, RegisteredServer, ServerState as ServerStateType, SignatureData,
        UserNameIdentityToken, UserTokenPolicy, UserTokenType, X509IdentityToken,
    },
    status_code::StatusCode,
};

use crate::server::{
    callbacks::{RegisterNodes, UnregisterNodes},
    config::{ServerConfig, ServerEndpoint},
    constants,
    diagnostics::ServerDiagnostics,
    events::{
        audit::{AuditEvent, AuditLog},
        event::Event,
    },
    historical::{HistoricalDataProvider, HistoricalEventProvider},
    identity_token::{
        IdentityToken, POLICY_ID_ANONYMOUS, POLICY_ID_USER_PASS_NONE, POLICY_ID_USER_PASS_RSA_15,
        POLICY_ID_USER_PASS_RSA_OAEP, POLICY_ID_X509,
    },
};

pub(crate) struct OperationalLimits {
    pub max_nodes_per_translate_browse_paths_to_node_ids: usize,
    pub max_nodes_per_read: usize,
    pub max_nodes_per_write: usize,
    pub max_nodes_per_method_call: usize,
    pub max_nodes_per_browse: usize,
    pub max_nodes_per_register_nodes: usize,
    pub max_nodes_per_node_management: usize,
    pub max_monitored_items_per_call: usize,
    pub max_nodes_per_history_read_data: usize,
    pub max_nodes_per_history_read_events: usize,
    pub max_nodes_per_history_update_data: usize,
    pub max_nodes_per_history_update_events: usize,
}

impl Default for OperationalLimits {
    fn default() -> Self {
        Self {
            max_nodes_per_translate_browse_paths_to_node_ids:
                constants::MAX_NODES_PER_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS,
            max_nodes_per_read: constants::MAX_NODES_PER_READ,
            max_nodes_per_write: constants::MAX_NODES_PER_WRITE,
            max_nodes_per_method_call: constants::MAX_NODES_PER_METHOD_CALL,
            max_nodes_per_browse: constants::MAX_NODES_PER_BROWSE,
            max_nodes_per_register_nodes: constants::MAX_NODES_PER_REGISTER_NODES,
            max_nodes_per_node_management: constants::MAX_NODES_PER_NODE_MANAGEMENT,
            max_monitored_items_per_call: constants::MAX_MONITORED_ITEMS_PER_CALL,
            max_nodes_per_history_read_data: constants::MAX_NODES_PER_HISTORY_READ_DATA,
            max_nodes_per_history_read_events: constants::MAX_NODES_PER_HISTORY_READ_EVENTS,
            max_nodes_per_history_update_data: constants::MAX_NODES_PER_HISTORY_UPDATE_DATA,
            max_nodes_per_history_update_events: constants::MAX_NODES_PER_HISTORY_UPDATE_EVENTS,
        }
    }
}

/// Server state is any state associated with the server as a whole that individual sessions might
/// be interested in. That includes configuration info etc.
pub struct ServerState {
    /// The application URI
    pub application_uri: UAString,
    /// The product URI
    pub product_uri: UAString,
    /// The application name
    pub application_name: LocalizedText,
    /// The protocol, hostname and port formatted as a url, but less the path
    pub base_endpoint: String,
    /// The time the server started
    pub start_time: DateTime,
    /// The list of servers (by urn)
    pub servers: Vec<String>,
    /// Server configuration
    pub config: Arc<RwLock<ServerConfig>>,
    /// Server public certificate read from config location or null if there is none
    pub server_certificate: Option<X509>,
    /// Server private key
    pub server_pkey: Option<PrivateKey>,
    /// The next subscription id - subscriptions are shared across the whole server. Initial value
    /// is a random u32.
    pub last_subscription_id: u32,
    /// Maximum number of subscriptions per session, 0 means no limit (danger)
    pub max_subscriptions: usize,
    /// Maximum number of monitored items per subscription, 0 means no limit (danger)
    pub max_monitored_items_per_sub: usize,
    /// Maximum number of queued values in a monitored item, 0 means no limit (danger)
    pub max_monitored_item_queue_size: usize,
    /// Minimum publishing interval (in millis)
    pub min_publishing_interval_ms: Duration,
    /// Minimum sampling interval (in millis)
    pub min_sampling_interval_ms: Duration,
    /// Default keep alive count
    pub default_keep_alive_count: u32,
    /// Maxmimum keep alive count
    pub max_keep_alive_count: u32,
    /// Maximum lifetime count (3 times as large as max keep alive)
    pub max_lifetime_count: u32,
    /// Operational limits
    pub(crate) operational_limits: OperationalLimits,
    /// Current state
    pub state: ServerStateType,
    /// Sets the abort flag that terminates the associated server
    pub abort: bool,
    /// Audit log
    pub(crate) audit_log: Arc<RwLock<AuditLog>>,
    /// Diagnostic information
    pub(crate) diagnostics: Arc<RwLock<ServerDiagnostics>>,
    /// Callback for register nodes
    pub(crate) register_nodes_callback: Option<Box<dyn RegisterNodes + Send + Sync>>,
    /// Callback for unregister nodes
    pub(crate) unregister_nodes_callback: Option<Box<dyn UnregisterNodes + Send + Sync>>,
    /// Callback for historical data
    pub(crate) historical_data_provider: Option<Box<dyn HistoricalDataProvider + Send + Sync>>,
    /// Callback for historical events
    pub(crate) historical_event_provider: Option<Box<dyn HistoricalEventProvider + Send + Sync>>,
    /// Size of the send buffer in bytes
    pub send_buffer_size: usize,
    /// Size of the receive buffer in bytes
    pub receive_buffer_size: usize,
}

impl ServerState {
    pub fn endpoints(
        &self,
        endpoint_url: &UAString,
        transport_profile_uris: &Option<Vec<UAString>>,
    ) -> Option<Vec<EndpointDescription>> {
        // Filter endpoints based on profile_uris
        debug!(
            "Endpoints requested, transport profile uris {:?}",
            transport_profile_uris
        );
        if let Some(ref transport_profile_uris) = *transport_profile_uris {
            // Note - some clients pass an empty array
            if !transport_profile_uris.is_empty() {
                // As we only support binary transport, the result is None if the supplied profile_uris does not contain that profile
                let found_binary_transport = transport_profile_uris.iter().any(|profile_uri| {
                    profile_uri.as_ref() == profiles::TRANSPORT_PROFILE_URI_BINARY
                });
                if !found_binary_transport {
                    error!(
                        "Client wants to connect with a non binary transport {:#?}",
                        transport_profile_uris
                    );
                    return None;
                }
            }
        }

        let config = trace_read_lock!(self.config);
        if let Ok(hostname) = hostname_from_url(endpoint_url.as_ref()) {
            if !hostname.eq_ignore_ascii_case(&config.tcp_config.host) {
                debug!("Endpoint url \"{}\" hostname supplied by caller does not match server's hostname \"{}\"", endpoint_url, &config.tcp_config.host);
            }
            let endpoints = config
                .endpoints
                .iter()
                .map(|(_, e)| self.new_endpoint_description(&config, e, true))
                .collect();
            Some(endpoints)
        } else {
            warn!(
                "Endpoint url \"{}\" is unrecognized, using default",
                endpoint_url
            );
            if let Some(e) = config.default_endpoint() {
                Some(vec![self.new_endpoint_description(&config, e, true)])
            } else {
                Some(vec![])
            }
        }
    }

    pub fn endpoint_exists(
        &self,
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> bool {
        let config = trace_read_lock!(self.config);
        config
            .find_endpoint(endpoint_url, security_policy, security_mode)
            .is_some()
    }

    /// Make matching endpoint descriptions for the specified url.
    /// If none match then None will be passed, therefore if Some is returned it will be guaranteed
    /// to contain at least one result.
    pub fn new_endpoint_descriptions(
        &self,
        endpoint_url: &str,
    ) -> Option<Vec<EndpointDescription>> {
        debug!("find_endpoint, url = {}", endpoint_url);
        let config = trace_read_lock!(self.config);
        let base_endpoint_url = config.base_endpoint_url();
        let endpoints: Vec<EndpointDescription> = config
            .endpoints
            .iter()
            .filter(|&(_, e)| {
                // Test end point's security_policy_uri and matching url
                url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url)
            })
            .map(|(_, e)| self.new_endpoint_description(&config, e, false))
            .collect();
        if endpoints.is_empty() {
            None
        } else {
            Some(endpoints)
        }
    }

    /// Determine what user/pass encryption to use depending on the security policy.
    fn user_pass_security_policy_id(endpoint: &ServerEndpoint) -> UAString {
        match endpoint.password_security_policy() {
            SecurityPolicy::None => POLICY_ID_USER_PASS_NONE,
            SecurityPolicy::Basic128Rsa15 => POLICY_ID_USER_PASS_RSA_15,
            SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => {
                POLICY_ID_USER_PASS_RSA_OAEP
            }
            // TODO this is a placeholder
            SecurityPolicy::Aes128Sha256RsaOaep | SecurityPolicy::Aes256Sha256RsaPss => {
                POLICY_ID_USER_PASS_RSA_OAEP
            }
            _ => {
                panic!()
            }
        }
        .into()
    }

    fn user_pass_security_policy_uri(_endpoint: &ServerEndpoint) -> UAString {
        // TODO we could force the security policy uri for passwords to be something other than the default
        //  here to ensure they're secure even when the endpoint's security policy is None.
        UAString::null()
    }

    fn user_identity_tokens(
        &self,
        config: &ServerConfig,
        endpoint: &ServerEndpoint,
    ) -> Vec<UserTokenPolicy> {
        let mut user_identity_tokens = Vec::with_capacity(3);

        // Anonymous policy
        if endpoint.supports_anonymous() {
            user_identity_tokens.push(UserTokenPolicy {
                policy_id: UAString::from(POLICY_ID_ANONYMOUS),
                token_type: UserTokenType::Anonymous,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::null(),
            });
        }
        // User pass policy
        if endpoint.supports_user_pass(&config.user_tokens) {
            // The endpoint may set a password security policy
            user_identity_tokens.push(UserTokenPolicy {
                policy_id: Self::user_pass_security_policy_id(endpoint),
                token_type: UserTokenType::UserName,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: Self::user_pass_security_policy_uri(endpoint),
            });
        }
        // X509 policy
        if endpoint.supports_x509(&config.user_tokens) {
            user_identity_tokens.push(UserTokenPolicy {
                policy_id: UAString::from(POLICY_ID_X509),
                token_type: UserTokenType::Certificate,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::from(SecurityPolicy::Basic128Rsa15.to_uri()),
            });
        }

        if user_identity_tokens.is_empty() {
            debug!(
                "user_identity_tokens() returned zero endpoints for endpoint {} / {} {}",
                endpoint.path, endpoint.security_policy, endpoint.security_mode
            );
        }

        user_identity_tokens
    }

    /// Constructs a new endpoint description using the server's info and that in an Endpoint
    fn new_endpoint_description(
        &self,
        config: &ServerConfig,
        endpoint: &ServerEndpoint,
        all_fields: bool,
    ) -> EndpointDescription {
        let base_endpoint_url = config.base_endpoint_url();

        let user_identity_tokens = self.user_identity_tokens(config, endpoint);

        // CreateSession doesn't need all the endpoint description
        // and docs say not to bother sending the server and server
        // certificate info.
        let (server, server_certificate) = if all_fields {
            (
                ApplicationDescription {
                    application_uri: self.application_uri.clone(),
                    product_uri: self.product_uri.clone(),
                    application_name: self.application_name.clone(),
                    application_type: self.application_type(),
                    gateway_server_uri: self.gateway_server_uri(),
                    discovery_profile_uri: UAString::null(),
                    discovery_urls: self.discovery_urls(),
                },
                self.server_certificate_as_byte_string(),
            )
        } else {
            (
                ApplicationDescription {
                    application_uri: UAString::null(),
                    product_uri: UAString::null(),
                    application_name: LocalizedText::null(),
                    application_type: self.application_type(),
                    gateway_server_uri: self.gateway_server_uri(),
                    discovery_profile_uri: UAString::null(),
                    discovery_urls: self.discovery_urls(),
                },
                ByteString::null(),
            )
        };

        EndpointDescription {
            endpoint_url: endpoint.endpoint_url(&base_endpoint_url).into(),
            server,
            server_certificate,
            security_mode: endpoint.message_security_mode(),
            security_policy_uri: UAString::from(endpoint.security_policy().to_uri()),
            user_identity_tokens: Some(user_identity_tokens),
            transport_profile_uri: UAString::from(profiles::TRANSPORT_PROFILE_URI_BINARY),
            security_level: endpoint.security_level,
        }
    }

    pub fn discovery_urls(&self) -> Option<Vec<UAString>> {
        let config = trace_read_lock!(self.config);
        if config.discovery_urls.is_empty() {
            None
        } else {
            Some(config.discovery_urls.iter().map(UAString::from).collect())
        }
    }

    pub fn application_type(&self) -> ApplicationType {
        ApplicationType::Server
    }

    pub fn gateway_server_uri(&self) -> UAString {
        UAString::null()
    }

    pub fn abort(&mut self) {
        info!("Server has been told to abort");
        self.abort = true;
        self.state = ServerStateType::Shutdown;
    }

    pub fn state(&self) -> ServerStateType {
        self.state
    }

    pub fn set_state(&mut self, state: ServerStateType) {
        self.state = state;
    }

    pub fn is_abort(&self) -> bool {
        self.abort
    }

    pub fn is_running(&self) -> bool {
        self.state == ServerStateType::Running
    }

    pub fn server_certificate_as_byte_string(&self) -> ByteString {
        if let Some(ref server_certificate) = self.server_certificate {
            server_certificate.as_byte_string()
        } else {
            ByteString::null()
        }
    }

    pub fn registered_server(&self) -> RegisteredServer {
        let server_uri = self.application_uri.clone();
        let product_uri = self.product_uri.clone();
        let gateway_server_uri = self.gateway_server_uri();
        let discovery_urls = self.discovery_urls();
        let server_type = self.application_type();
        let is_online = self.is_running();
        let server_names = Some(vec![self.application_name.clone()]);
        // Server names
        RegisteredServer {
            server_uri,
            product_uri,
            server_names,
            server_type,
            gateway_server_uri,
            discovery_urls,
            semaphore_file_path: UAString::null(),
            is_online,
        }
    }

    pub fn create_subscription_id(&mut self) -> u32 {
        self.last_subscription_id += 1;
        self.last_subscription_id
    }

    /// Authenticates access to an endpoint. The endpoint is described by its path, policy, mode and
    /// the token is supplied in an extension object that must be extracted and authenticated.
    ///
    /// It is possible that the endpoint does not exist, or that the token is invalid / unsupported
    /// or that the token cannot be used with the end point. The return codes reflect the responses
    /// that ActivateSession would expect from a service call.
    pub fn authenticate_endpoint(
        &self,
        request: &ActivateSessionRequest,
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
        user_identity_token: &ExtensionObject,
        server_nonce: &ByteString,
    ) -> Result<String, StatusCode> {
        // Get security from endpoint url
        let config = trace_read_lock!(self.config);

        if let Some(endpoint) = config.find_endpoint(endpoint_url, security_policy, security_mode) {
            // Now validate the user identity token
            match IdentityToken::new(user_identity_token, &self.decoding_options()) {
                IdentityToken::None => {
                    error!("User identity token type unsupported");
                    Err(StatusCode::BadIdentityTokenInvalid)
                }
                IdentityToken::AnonymousIdentityToken(token) => {
                    Self::authenticate_anonymous_token(endpoint, &token)
                }
                IdentityToken::UserNameIdentityToken(token) => self
                    .authenticate_username_identity_token(
                        &config,
                        endpoint,
                        &token,
                        &self.server_pkey,
                        server_nonce,
                    ),
                IdentityToken::X509IdentityToken(token) => self.authenticate_x509_identity_token(
                    &config,
                    endpoint,
                    &token,
                    &request.user_token_signature,
                    &self.server_certificate,
                    server_nonce,
                ),
                IdentityToken::Invalid(o) => {
                    error!("User identity token type {:?} is unsupported", o.node_id);
                    Err(StatusCode::BadIdentityTokenInvalid)
                }
            }
        } else {
            error!("Cannot find endpoint that matches path \"{}\", security policy {:?}, and security mode {:?}", endpoint_url, security_policy, security_mode);
            Err(StatusCode::BadTcpEndpointUrlInvalid)
        }
    }

    pub fn set_register_nodes_callbacks(
        &mut self,
        register_nodes_callback: Box<dyn RegisterNodes + Send + Sync>,
        unregister_nodes_callback: Box<dyn UnregisterNodes + Send + Sync>,
    ) {
        self.register_nodes_callback = Some(register_nodes_callback);
        self.unregister_nodes_callback = Some(unregister_nodes_callback);
    }

    /// Returns the decoding options of the server
    pub fn decoding_options(&self) -> DecodingOptions {
        let config = trace_read_lock!(self.config);
        config.decoding_options()
    }

    /// Authenticates an anonymous token, i.e. does the endpoint support anonymous access or not
    fn authenticate_anonymous_token(
        endpoint: &ServerEndpoint,
        token: &AnonymousIdentityToken,
    ) -> Result<String, StatusCode> {
        if token.policy_id.as_ref() != POLICY_ID_ANONYMOUS {
            error!("Token doesn't possess the correct policy id");
            Err(StatusCode::BadIdentityTokenInvalid)
        } else if !endpoint.supports_anonymous() {
            error!(
                "Endpoint \"{}\" does not support anonymous authentication",
                endpoint.path
            );
            Err(StatusCode::BadIdentityTokenRejected)
        } else {
            debug!("Anonymous identity is authenticated");
            Ok(String::from(crate::server::config::ANONYMOUS_USER_TOKEN_ID))
        }
    }

    /// Authenticates the username identity token with the supplied endpoint. The function returns the user token identifier
    /// that matches the identity token.
    fn authenticate_username_identity_token(
        &self,
        config: &ServerConfig,
        endpoint: &ServerEndpoint,
        token: &UserNameIdentityToken,
        server_key: &Option<PrivateKey>,
        server_nonce: &ByteString,
    ) -> Result<String, StatusCode> {
        if !endpoint.supports_user_pass(&config.user_tokens) {
            error!("Endpoint doesn't support username password tokens");
            Err(StatusCode::BadIdentityTokenRejected)
        } else if token.policy_id != Self::user_pass_security_policy_id(endpoint) {
            error!("Token doesn't possess the correct policy id");
            Err(StatusCode::BadIdentityTokenInvalid)
        } else if token.user_name.is_null() {
            error!("User identify token supplies no user name");
            Err(StatusCode::BadIdentityTokenInvalid)
        } else {
            debug!(
                "policy id = {}, encryption algorithm = {}",
                token.policy_id.as_ref(),
                token.encryption_algorithm.as_ref()
            );
            let token_password = if !token.encryption_algorithm.is_null() {
                if let Some(ref server_key) = server_key {
                    user_identity::decrypt_user_identity_token_password(
                        token,
                        server_nonce.as_ref(),
                        server_key,
                    )?
                } else {
                    error!("Identity token password is encrypted but no server private key was supplied");
                    return Err(StatusCode::BadIdentityTokenInvalid);
                }
            } else {
                token.plaintext_password()?
            };

            // Iterate ids in endpoint
            for user_token_id in &endpoint.user_token_ids {
                if let Some(server_user_token) = config.user_tokens.get(user_token_id) {
                    if server_user_token.is_user_pass()
                        && server_user_token.user == token.user_name.as_ref()
                    {
                        // test for empty password
                        let valid = if server_user_token.pass.is_none() {
                            // Empty password for user
                            token_password.is_empty()
                        } else {
                            // Password compared as UTF-8 bytes
                            let server_password =
                                server_user_token.pass.as_ref().unwrap().as_bytes();
                            server_password == token_password.as_bytes()
                        };
                        if !valid {
                            error!(
                                "Cannot authenticate \"{}\", password is invalid",
                                server_user_token.user
                            );
                            return Err(StatusCode::BadUserAccessDenied);
                        } else {
                            return Ok(user_token_id.clone());
                        }
                    }
                }
            }
            error!(
                "Cannot authenticate \"{}\", user not found for endpoint",
                token.user_name
            );
            Err(StatusCode::BadUserAccessDenied)
        }
    }

    /// Authenticate the x509 token against the endpoint. The function returns the user token identifier
    /// that matches the identity token.
    fn authenticate_x509_identity_token(
        &self,
        config: &ServerConfig,
        endpoint: &ServerEndpoint,
        token: &X509IdentityToken,
        user_token_signature: &SignatureData,
        server_certificate: &Option<X509>,
        server_nonce: &ByteString,
    ) -> Result<String, StatusCode> {
        if !endpoint.supports_x509(&config.user_tokens) {
            error!("Endpoint doesn't support x509 tokens");
            Err(StatusCode::BadIdentityTokenRejected)
        } else if token.policy_id.as_ref() != POLICY_ID_X509 {
            error!("Token doesn't possess the correct policy id");
            Err(StatusCode::BadIdentityTokenRejected)
        } else {
            let result = match server_certificate {
                Some(ref server_certificate) => {
                    // Find the security policy used for verifying tokens
                    let user_identity_tokens = self.user_identity_tokens(config, endpoint);
                    let security_policy = user_identity_tokens
                        .iter()
                        .find(|t| t.token_type == UserTokenType::Certificate)
                        .map(|t| SecurityPolicy::from_uri(t.security_policy_uri.as_ref()))
                        .unwrap_or_else(|| endpoint.security_policy());

                    // The security policy has to be something that can encrypt
                    match security_policy {
                        SecurityPolicy::Unknown | SecurityPolicy::None => {
                            Err(StatusCode::BadIdentityTokenInvalid)
                        }
                        security_policy => {
                            // Verify token
                            user_identity::verify_x509_identity_token(
                                token,
                                user_token_signature,
                                security_policy,
                                server_certificate,
                                server_nonce.as_ref(),
                            )
                        }
                    }
                }
                None => Err(StatusCode::BadIdentityTokenInvalid),
            };
            result.and_then(|_| {
                // Check the endpoint to see if this token is supported
                let signing_cert = X509::from_byte_string(&token.certificate_data)?;
                let signing_thumbprint = signing_cert.thumbprint();
                for user_token_id in &endpoint.user_token_ids {
                    if let Some(server_user_token) = config.user_tokens.get(user_token_id) {
                        if let Some(ref user_thumbprint) = server_user_token.thumbprint {
                            // The signing cert matches a user's identity, so it is valid
                            if *user_thumbprint == signing_thumbprint {
                                return Ok(user_token_id.clone());
                            }
                        }
                    }
                }
                Err(StatusCode::BadIdentityTokenInvalid)
            })
        }
    }

    pub fn set_historical_data_provider(
        &mut self,
        historical_data_provider: Box<dyn HistoricalDataProvider + Send + Sync>,
    ) {
        self.historical_data_provider = Some(historical_data_provider);
    }

    pub fn set_historical_event_provider(
        &mut self,
        historical_event_provider: Box<dyn HistoricalEventProvider + Send + Sync>,
    ) {
        self.historical_event_provider = Some(historical_event_provider);
    }

    pub(crate) fn raise_and_log<T>(&self, event: T) -> Result<NodeId, ()>
    where
        T: AuditEvent + Event,
    {
        let audit_log = trace_write_lock!(self.audit_log);
        audit_log.raise_and_log(event)
    }
}
