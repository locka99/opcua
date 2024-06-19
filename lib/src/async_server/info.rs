// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Provides server state information, such as status, configuration, running servers and so on.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::async_server::authenticator::Password;
use crate::core::handle::AtomicHandle;
use crate::core::prelude::*;
use crate::crypto::{user_identity, PrivateKey, SecurityPolicy, X509};
use crate::sync::RwLock;
use crate::types::{
    profiles,
    service_types::{
        ActivateSessionRequest, AnonymousIdentityToken, ApplicationDescription, ApplicationType,
        EndpointDescription, RegisteredServer, ServerState as ServerStateType, SignatureData,
        UserNameIdentityToken, UserTokenPolicy, UserTokenType, X509IdentityToken,
    },
    status_code::StatusCode,
};

use crate::async_server::{
    config::{ServerConfig, ServerEndpoint},
    constants,
};

use super::authenticator::{AuthManager, UserToken};
use super::identity_token::{
    IdentityToken, POLICY_ID_ANONYMOUS, POLICY_ID_USER_PASS_NONE, POLICY_ID_USER_PASS_RSA_15,
    POLICY_ID_USER_PASS_RSA_OAEP, POLICY_ID_X509,
};
use super::node_manager::TypeTree;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct OperationalLimits {
    #[serde(default = "defaults::max_nodes_per_translate_browse_paths_to_node_ids")]
    pub max_nodes_per_translate_browse_paths_to_node_ids: usize,
    #[serde(default = "defaults::max_nodes_per_read")]
    pub max_nodes_per_read: usize,
    #[serde(default = "defaults::max_nodes_per_write")]
    pub max_nodes_per_write: usize,
    #[serde(default = "defaults::max_nodes_per_method_call")]
    pub max_nodes_per_method_call: usize,
    #[serde(default = "defaults::max_nodes_per_browse")]
    pub max_nodes_per_browse: usize,
    #[serde(default = "defaults::max_nodes_per_register_nodes")]
    pub max_nodes_per_register_nodes: usize,
    #[serde(default = "defaults::max_monitored_items_per_call")]
    pub max_monitored_items_per_call: usize,
    #[serde(default = "defaults::max_nodes_per_history_read_data")]
    pub max_nodes_per_history_read_data: usize,
    #[serde(default = "defaults::max_nodes_per_history_read_events")]
    pub max_nodes_per_history_read_events: usize,
    #[serde(default = "defaults::max_nodes_per_history_update")]
    pub max_nodes_per_history_update: usize,
    #[serde(default = "defaults::max_references_per_browse_node")]
    pub max_references_per_browse_node: usize,
    #[serde(default = "defaults::max_node_descs_per_query")]
    pub max_node_descs_per_query: usize,
    #[serde(default = "defaults::max_data_sets_query_return")]
    pub max_data_sets_query_return: usize,
    #[serde(default = "defaults::max_references_query_return")]
    pub max_references_query_return: usize,
    #[serde(default = "defaults::max_nodes_per_node_management")]
    pub max_nodes_per_node_management: usize,
    #[serde(default = "defaults::max_references_per_references_management")]
    pub max_references_per_references_management: usize,
}

mod defaults {
    use crate::async_server::constants;

    pub fn max_nodes_per_translate_browse_paths_to_node_ids() -> usize {
        constants::MAX_NODES_PER_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS
    }
    pub fn max_nodes_per_read() -> usize {
        constants::MAX_NODES_PER_READ
    }
    pub fn max_nodes_per_write() -> usize {
        constants::MAX_NODES_PER_WRITE
    }
    pub fn max_nodes_per_method_call() -> usize {
        constants::MAX_NODES_PER_METHOD_CALL
    }
    pub fn max_nodes_per_browse() -> usize {
        constants::MAX_NODES_PER_BROWSE
    }
    pub fn max_nodes_per_register_nodes() -> usize {
        constants::MAX_NODES_PER_REGISTER_NODES
    }
    pub fn max_monitored_items_per_call() -> usize {
        constants::MAX_MONITORED_ITEMS_PER_CALL
    }
    pub fn max_nodes_per_history_read_data() -> usize {
        constants::MAX_NODES_PER_HISTORY_READ_DATA
    }
    pub fn max_nodes_per_history_read_events() -> usize {
        constants::MAX_NODES_PER_HISTORY_READ_EVENTS
    }
    pub fn max_nodes_per_history_update() -> usize {
        constants::MAX_NODES_PER_HISTORY_UPDATE
    }
    pub fn max_references_per_browse_node() -> usize {
        constants::MAX_REFERENCES_PER_BROWSE_NODE
    }
    pub fn max_node_descs_per_query() -> usize {
        constants::MAX_NODE_DESCS_PER_QUERY
    }
    pub fn max_data_sets_query_return() -> usize {
        constants::MAX_DATA_SETS_QUERY_RETURN
    }
    pub fn max_references_query_return() -> usize {
        constants::MAX_REFERENCES_QUERY_RETURN
    }
    pub fn max_nodes_per_node_management() -> usize {
        constants::MAX_NODES_PER_NODE_MANAGEMENT
    }
    pub fn max_references_per_references_management() -> usize {
        constants::MAX_REFERENCES_PER_REFERENCE_MANAGEMENT
    }
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
            max_monitored_items_per_call: constants::MAX_MONITORED_ITEMS_PER_CALL,
            max_nodes_per_history_read_data: constants::MAX_NODES_PER_HISTORY_READ_DATA,
            max_nodes_per_history_read_events: constants::MAX_NODES_PER_HISTORY_READ_EVENTS,
            max_nodes_per_history_update: constants::MAX_NODES_PER_HISTORY_UPDATE,
            max_references_per_browse_node: constants::MAX_REFERENCES_PER_BROWSE_NODE,
            max_node_descs_per_query: constants::MAX_NODE_DESCS_PER_QUERY,
            max_data_sets_query_return: constants::MAX_DATA_SETS_QUERY_RETURN,
            max_references_query_return: constants::MAX_REFERENCES_QUERY_RETURN,
            max_nodes_per_node_management: constants::MAX_NODES_PER_NODE_MANAGEMENT,
            max_references_per_references_management:
                constants::MAX_REFERENCES_PER_REFERENCE_MANAGEMENT,
        }
    }
}

/// Server state is any configuration associated with the server as a whole that individual sessions might
/// be interested in.
pub struct ServerInfo {
    /// The application URI
    pub application_uri: UAString,
    /// The product URI
    pub product_uri: UAString,
    /// The application name
    pub application_name: LocalizedText,
    /// The protocol, hostname and port formatted as a url, but less the path
    pub base_endpoint: String,
    /// The time the server started
    pub start_time: ArcSwap<DateTime>,
    /// The list of servers (by urn)
    pub servers: Vec<String>,
    /// Server configuration
    pub config: Arc<ServerConfig>,
    /// Server public certificate read from config location or null if there is none
    pub server_certificate: Option<X509>,
    /// Server private key
    pub server_pkey: Option<PrivateKey>,
    /// Operational limits
    pub(crate) operational_limits: OperationalLimits,
    /// Current state
    pub state: ArcSwap<ServerStateType>,
    /// Audit log
    // pub(crate) audit_log: Arc<RwLock<AuditLog>>,
    /// Diagnostic information
    // pub(crate) diagnostics: Arc<RwLock<ServerDiagnostics>>,
    /// Size of the send buffer in bytes
    pub send_buffer_size: usize,
    /// Size of the receive buffer in bytes
    pub receive_buffer_size: usize,
    /// Authenticator to use when verifying user identities, and checking for user access.
    pub authenticator: Arc<dyn AuthManager>,
    /// Structure containing type metadata shared by the entire server.
    pub type_tree: Arc<RwLock<TypeTree>>,
    /// Generator for subscription IDs.
    pub subscription_id_handle: AtomicHandle,
    /// Generator for monitored item IDs.
    pub monitored_item_id_handle: AtomicHandle,
}

impl ServerInfo {
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

        if let Ok(hostname) = hostname_from_url(endpoint_url.as_ref()) {
            if !hostname.eq_ignore_ascii_case(&self.config.tcp_config.host) {
                debug!("Endpoint url \"{}\" hostname supplied by caller does not match server's hostname \"{}\"", endpoint_url, &self.config.tcp_config.host);
            }
            let endpoints = self
                .config
                .endpoints
                .iter()
                .map(|(_, e)| self.new_endpoint_description(e, true))
                .collect();
            Some(endpoints)
        } else {
            warn!(
                "Endpoint url \"{}\" is unrecognized, using default",
                endpoint_url
            );
            if let Some(e) = self.config.default_endpoint() {
                Some(vec![self.new_endpoint_description(e, true)])
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
        self.config
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
        let base_endpoint_url = self.config.base_endpoint_url();
        let endpoints: Vec<EndpointDescription> = self
            .config
            .endpoints
            .iter()
            .filter(|&(_, e)| {
                // Test end point's security_policy_uri and matching url
                url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url)
            })
            .map(|(_, e)| self.new_endpoint_description(e, false))
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

    fn user_identity_tokens(&self, endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
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
        if endpoint.supports_user_pass(&self.config.user_tokens) {
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
        if endpoint.supports_x509(&self.config.user_tokens) {
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
        endpoint: &ServerEndpoint,
        all_fields: bool,
    ) -> EndpointDescription {
        let base_endpoint_url = self.config.base_endpoint_url();

        let user_identity_tokens = self.user_identity_tokens(endpoint);

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
        if self.config.discovery_urls.is_empty() {
            None
        } else {
            Some(
                self.config
                    .discovery_urls
                    .iter()
                    .map(UAString::from)
                    .collect(),
            )
        }
    }

    pub fn application_type(&self) -> ApplicationType {
        ApplicationType::Server
    }

    pub fn gateway_server_uri(&self) -> UAString {
        UAString::null()
    }

    pub fn state(&self) -> ServerStateType {
        **self.state.load()
    }

    pub fn set_state(&self, state: ServerStateType) {
        self.state.store(Arc::new(state));
    }

    pub fn is_running(&self) -> bool {
        self.state() == ServerStateType::Running
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

    /// Authenticates access to an endpoint. The endpoint is described by its path, policy, mode and
    /// the token is supplied in an extension object that must be extracted and authenticated.
    ///
    /// It is possible that the endpoint does not exist, or that the token is invalid / unsupported
    /// or that the token cannot be used with the end point. The return codes reflect the responses
    /// that ActivateSession would expect from a service call.
    pub async fn authenticate_endpoint(
        &self,
        request: &ActivateSessionRequest,
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
        user_identity_token: &ExtensionObject,
        server_nonce: &ByteString,
    ) -> Result<UserToken, StatusCode> {
        // Get security from endpoint url
        if let Some(endpoint) =
            self.config
                .find_endpoint(endpoint_url, security_policy, security_mode)
        {
            // Now validate the user identity token
            match IdentityToken::new(user_identity_token, &self.decoding_options()) {
                IdentityToken::None => {
                    error!("User identity token type unsupported");
                    Err(StatusCode::BadIdentityTokenInvalid)
                }
                IdentityToken::AnonymousIdentityToken(token) => {
                    self.authenticate_anonymous_token(endpoint, &token).await
                }
                IdentityToken::UserNameIdentityToken(token) => {
                    self.authenticate_username_identity_token(
                        endpoint,
                        &token,
                        &self.server_pkey,
                        server_nonce,
                    )
                    .await
                }
                IdentityToken::X509IdentityToken(token) => {
                    self.authenticate_x509_identity_token(
                        endpoint,
                        &token,
                        &request.user_token_signature,
                        &self.server_certificate,
                        server_nonce,
                    )
                    .await
                }
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

    /// Returns the decoding options of the server
    pub fn decoding_options(&self) -> DecodingOptions {
        self.config.decoding_options()
    }

    /// Authenticates an anonymous token, i.e. does the endpoint support anonymous access or not
    async fn authenticate_anonymous_token(
        &self,
        endpoint: &ServerEndpoint,
        token: &AnonymousIdentityToken,
    ) -> Result<UserToken, StatusCode> {
        if token.policy_id.as_ref() != POLICY_ID_ANONYMOUS {
            error!("Token doesn't possess the correct policy id");
            return Err(StatusCode::BadIdentityTokenInvalid);
        }
        self.authenticator
            .authenticate_anonymous_token(endpoint)
            .await
    }

    /// Authenticates the username identity token with the supplied endpoint. The function returns the user token identifier
    /// that matches the identity token.
    async fn authenticate_username_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        token: &UserNameIdentityToken,
        server_key: &Option<PrivateKey>,
        server_nonce: &ByteString,
    ) -> Result<UserToken, StatusCode> {
        if !endpoint.supports_user_pass(&self.config.user_tokens) {
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

            self.authenticator
                .authenticate_username_identity_token(
                    endpoint,
                    token.user_name.as_ref(),
                    &Password::new(token_password),
                )
                .await
        }
    }

    /// Authenticate the x509 token against the endpoint. The function returns the user token identifier
    /// that matches the identity token.
    async fn authenticate_x509_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        token: &X509IdentityToken,
        user_token_signature: &SignatureData,
        server_certificate: &Option<X509>,
        server_nonce: &ByteString,
    ) -> Result<UserToken, StatusCode> {
        if !endpoint.supports_x509(&self.config.user_tokens) {
            error!("Endpoint doesn't support x509 tokens");
            Err(StatusCode::BadIdentityTokenRejected)
        } else if token.policy_id.as_ref() != POLICY_ID_X509 {
            error!("Token doesn't possess the correct policy id");
            Err(StatusCode::BadIdentityTokenRejected)
        } else {
            match server_certificate {
                Some(ref server_certificate) => {
                    // Find the security policy used for verifying tokens
                    let user_identity_tokens = self.user_identity_tokens(endpoint);
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
            }?;

            // Check the endpoint to see if this token is supported
            let signing_cert = X509::from_byte_string(&token.certificate_data)?;
            let signing_thumbprint = signing_cert.thumbprint();

            self.authenticator
                .authenticate_x509_identity_token(&signing_thumbprint, endpoint)
                .await
        }
    }

    /* pub(crate) fn raise_and_log<T>(&self, event: T) -> Result<NodeId, ()>
    where
        T: AuditEvent + Event,
    {
        let audit_log = trace_write_lock!(self.audit_log);
        audit_log.raise_and_log(event)
    } */
}
