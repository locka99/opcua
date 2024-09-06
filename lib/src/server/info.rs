// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Provides server state information, such as status, configuration, running servers and so on.

use std::sync::atomic::{AtomicU16, AtomicU8, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::core::comms::url::{hostname_from_url, url_matches_except_host};
use crate::core::handle::AtomicHandle;
use crate::crypto::{user_identity, PrivateKey, SecurityPolicy, X509};
use crate::server::authenticator::Password;
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
use crate::types::{
    AttributeId, ByteString, DataValue, DateTime, DecodingOptions, ExtensionObject, LocalizedText,
    MessageSecurityMode, UAString, VariableId,
};

use crate::server::config::{ServerConfig, ServerEndpoint};

use super::authenticator::{AuthManager, UserToken};
use super::identity_token::{
    IdentityToken, POLICY_ID_ANONYMOUS, POLICY_ID_USER_PASS_NONE, POLICY_ID_USER_PASS_RSA_15,
    POLICY_ID_USER_PASS_RSA_OAEP, POLICY_ID_X509,
};
use super::node_manager::TypeTree;
use super::{OperationalLimits, ServerCapabilities, SubscriptionCache, ANONYMOUS_USER_TOKEN_ID};

/// Server state is any configuration associated with the server as a whole that individual sessions might
/// be interested in.
pub struct ServerInfo {
    /// The application URI
    pub application_uri: UAString,
    /// The product URI
    pub product_uri: UAString,
    /// The application name
    pub application_name: LocalizedText,
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
    /// Generator for secure channel IDs.
    pub secure_channel_id_handle: Arc<AtomicHandle>,
    /// Server capabilities
    pub capabilities: ServerCapabilities,
    /// Service level observer.
    pub service_level: Arc<AtomicU8>,
    /// Currently active local port.
    pub port: AtomicU16,
}

impl ServerInfo {
    /// Get the list of endpoints that match the provided filters.
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

    /// Check if the endpoint given by `endpoint_url`, `security_policy`, and `security_mode`
    /// exists on the server.
    pub fn endpoint_exists(
        &self,
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> bool {
        self.config
            .find_endpoint(
                endpoint_url,
                &self.base_endpoint(),
                security_policy,
                security_mode,
            )
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
        let base_endpoint_url = self.base_endpoint();
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
        let base_endpoint_url = self.base_endpoint();

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

    /// Get the list of discovery URLs on the server.
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

    /// Get the application type, will be `Server`.
    pub fn application_type(&self) -> ApplicationType {
        ApplicationType::Server
    }

    /// Get the gateway server URI.
    pub fn gateway_server_uri(&self) -> UAString {
        UAString::null()
    }

    /// Get the current server state.
    pub fn state(&self) -> ServerStateType {
        **self.state.load()
    }

    /// Set the server state. Note that this does not actually affect the server, it is purely
    /// informative.
    pub(crate) fn set_state(&self, state: ServerStateType, subs: &SubscriptionCache) {
        self.state.store(Arc::new(state));
        subs.notify_data_change(
            [(
                DataValue::new_now(state as i32),
                &VariableId::Server_ServerStatus.into(),
                AttributeId::Value,
            )]
            .into_iter(),
        );
    }

    /// Check if the server state indicates the server is running.
    pub fn is_running(&self) -> bool {
        self.state() == ServerStateType::Running
    }

    /// Get the base endpoint, i.e. the configured host + current port.
    pub fn base_endpoint(&self) -> String {
        format!(
            "opc.tcp://{}:{}",
            self.config.tcp_config.host,
            self.port.load(Ordering::Relaxed)
        )
    }

    /// Get the server certificate as a byte string.
    pub fn server_certificate_as_byte_string(&self) -> ByteString {
        if let Some(ref server_certificate) = self.server_certificate {
            server_certificate.as_byte_string()
        } else {
            ByteString::null()
        }
    }

    /// Get a representation of this server as a `RegisteredServer` object.
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
        if let Some(endpoint) = self.config.find_endpoint(
            endpoint_url,
            &self.base_endpoint(),
            security_policy,
            security_mode,
        ) {
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
            .await?;

        Ok(UserToken(ANONYMOUS_USER_TOKEN_ID.to_string()))
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
                .authenticate_x509_identity_token(endpoint, &signing_thumbprint)
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
