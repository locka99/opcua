//! Provides server state information, such as status, configuration, running servers and so on.

use std::sync::{Arc, RwLock};

use opcua_core::prelude::*;
use opcua_core::crypto::user_identity;

use opcua_types::{
    node_ids::ObjectId,
    profiles,
    service_types::{
        ActivateSessionRequest, ApplicationDescription, RegisteredServer, ApplicationType, EndpointDescription,
        AnonymousIdentityToken, UserNameIdentityToken, UserTokenPolicy, UserTokenType, X509IdentityToken, SignatureData,
        ServerState as ServerStateType,
    },
    status_code::StatusCode,
};

use crate::config::{ServerConfig, ServerEndpoint};
use crate::diagnostics::ServerDiagnostics;
use crate::callbacks::{RegisterNodes, UnregisterNodes};

pub(crate) const POLICY_ID_ANONYMOUS: &str = "anonymous";
pub(crate) const POLICY_ID_USER_PASS_NONE: &str = "userpass_none";
pub(crate) const POLICY_ID_USER_PASS_RSA_15: &str = "userpass_rsa_15";
pub(crate) const POLICY_ID_USER_PASS_RSA_OAEP: &str = "userpass_rsa_oaep";
pub(crate) const POLICY_ID_X509: &str = "x509";

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
    /// The list of namespaces
    pub namespaces: Vec<String>,
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
    /// Limits on method service
    pub max_method_calls: usize,
    /// Limits on node management service
    pub max_nodes_per_node_management: usize,
    /// Limits on view service
    pub max_browse_paths_per_translate: usize,
    //// Current state
    pub state: ServerStateType,
    /// Sets the abort flag that terminates the associated server
    pub abort: bool,
    /// Diagnostic information
    pub diagnostics: Arc<RwLock<ServerDiagnostics>>,
    /// Callback for register nodes
    pub(crate) register_nodes_callback: Option<Box<RegisterNodes + Send + Sync>>,
    /// Callback for unregister nodes
    pub(crate) unregister_nodes_callback: Option<Box<UnregisterNodes + Send + Sync>>,

}

impl ServerState {
    pub fn endpoints(&self, transport_profile_uris: &Option<Vec<UAString>>) -> Option<Vec<EndpointDescription>> {
        // Filter endpoints based on profile_uris
        debug!("Endpoints requested {:?}", transport_profile_uris);
        if let Some(ref transport_profile_uris) = *transport_profile_uris {
            if !transport_profile_uris.is_empty() {
                // As we only support binary transport, the result is None if the supplied profile_uris does not contain that profile
                let found_binary_transport = transport_profile_uris.iter().any(|profile_uri| {
                    profile_uri.as_ref() == profiles::TRANSPORT_PROFILE_URI_BINARY
                });
                if !found_binary_transport {
                    error!("Client wants to connect with a non binary transport {:#?}", transport_profile_uris);
                    return None;
                }
            }
        }
        // Return the endpoints
        let config = trace_read_lock_unwrap!(self.config);
        Some(config.endpoints.iter().map(|(_, e)| {
            self.new_endpoint_description(&config, e, true)
        }).collect())
    }

    pub fn endpoint_exists(&self, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> bool {
        let config = trace_read_lock_unwrap!(self.config);
        config.find_endpoint(endpoint_url, security_policy, security_mode).is_some()
    }

    /// Make matching endpoint descriptions for the specified url.
    /// If none match then None will be passed, therefore if Some is returned it will be guaranteed
    /// to contain at least one result.
    pub fn new_endpoint_descriptions(&self, endpoint_url: &str) -> Option<Vec<EndpointDescription>> {
        debug!("find_endpoint, url = {}", endpoint_url);
        let config = trace_read_lock_unwrap!(self.config);
        let base_endpoint_url = config.base_endpoint_url();
        let endpoints: Vec<EndpointDescription> = config.endpoints.iter().filter(|&(_, e)| {
            // Test end point's security_policy_uri and matching url
            url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url)
        }).map(|(_, e)| self.new_endpoint_description(&config, e, false)).collect();
        if endpoints.is_empty() { None } else { Some(endpoints) }
    }

    fn user_pass_security_policy_id(endpoint: &ServerEndpoint) -> UAString {
        match endpoint.password_security_policy() {
            SecurityPolicy::None => POLICY_ID_USER_PASS_NONE,
            SecurityPolicy::Basic128Rsa15 => POLICY_ID_USER_PASS_RSA_15,
            SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => POLICY_ID_USER_PASS_RSA_OAEP,
            _ => { panic!() }
        }.into()
    }

    fn user_pass_security_policy_uri(_endpoint: &ServerEndpoint) -> UAString {
        // TODO we could force the security policy uri for passwords to be something other than the default
        // here to ensure they're secure even when the endpoint's security policy is None.
        UAString::null()
    }

    /// Constructs a new endpoint description using the server's info and that in an Endpoint
    fn new_endpoint_description(&self, config: &ServerConfig, endpoint: &ServerEndpoint, all_fields: bool) -> EndpointDescription {
        let base_endpoint_url = config.base_endpoint_url();

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
                token_type: UserTokenType::Username,
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
                security_policy_uri: UAString::null(),
            });
        }

        // user_identity_tokens.iter().for_each(|t| debug!("  {:?}", t));

        // CreateSession doesn't need all the endpoint description
        // and docs say not to bother sending the server and server
        // certificate info.
        let (server, server_certificate) = if all_fields {
            (ApplicationDescription {
                application_uri: self.application_uri.clone(),
                product_uri: self.product_uri.clone(),
                application_name: self.application_name.clone(),
                application_type: self.application_type(),
                gateway_server_uri: self.gateway_server_uri(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: self.discovery_urls(),
            }, self.server_certificate_as_byte_string())
        } else {
            (ApplicationDescription {
                application_uri: UAString::null(),
                product_uri: UAString::null(),
                application_name: LocalizedText::null(),
                application_type: self.application_type(),
                gateway_server_uri: self.gateway_server_uri(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: self.discovery_urls(),
            }, ByteString::null())
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
        let config = trace_read_lock_unwrap!(self.config);
        if config.discovery_urls.is_empty() {
            None
        } else {
            Some(config.discovery_urls.iter().map(|url| UAString::from(url)).collect())
        }
    }

    pub fn application_type(&self) -> ApplicationType { ApplicationType::Server }

    pub fn gateway_server_uri(&self) -> UAString { UAString::null() }

    pub fn abort(&mut self) {
        info!("Server has been told to abort");
        self.abort = true;
        self.state = ServerStateType::Shutdown;
    }

    pub fn state(&self) -> ServerStateType { self.state }

    pub fn set_state(&mut self, state: ServerStateType) {
        self.state = state;
    }

    pub fn is_abort(&self) -> bool { self.abort }

    pub fn is_running(&self) -> bool { self.state == ServerStateType::Running }

    pub fn max_method_calls(&self) -> usize {
        self.max_method_calls
    }

    pub fn max_nodes_per_node_management(&self) -> usize {
        self.max_nodes_per_node_management
    }

    pub fn max_browse_paths_per_translate(&self) -> usize {
        self.max_browse_paths_per_translate
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
    pub fn authenticate_endpoint(&self, request: &ActivateSessionRequest, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode, user_identity_token: &ExtensionObject, server_nonce: &ByteString) -> Result<String, StatusCode> {
        // Get security from endpoint url
        let config = trace_read_lock_unwrap!(self.config);
        let decoding_limits = config.decoding_limits();
        if let Some(endpoint) = config.find_endpoint(endpoint_url, security_policy, security_mode) {
            // Now validate the user identity token
            if user_identity_token.is_empty() {
                // Empty tokens are treated as anonymous
                Self::authenticate_anonymous_token(endpoint, &AnonymousIdentityToken {
                    policy_id: UAString::from(POLICY_ID_ANONYMOUS)
                })
            } else if let Ok(object_id) = user_identity_token.node_id.as_object_id() {
                // Read the token out from the extension object
                match object_id {
                    ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary => {
                        if let Ok(token) = user_identity_token.decode_inner::<AnonymousIdentityToken>(&decoding_limits) {
                            // Anonymous
                            Self::authenticate_anonymous_token(endpoint, &token)
                        } else {
                            // Garbage in the extension object
                            error!("Anonymous identity token could not be decoded");
                            Err(StatusCode::BadIdentityTokenInvalid)
                        }
                    }
                    ObjectId::UserNameIdentityToken_Encoding_DefaultBinary => {
                        // Username / password
                        if let Ok(token) = user_identity_token.decode_inner::<UserNameIdentityToken>(&decoding_limits) {
                            self.authenticate_username_identity_token(&config, endpoint, &token, &self.server_pkey, server_nonce)
                        } else {
                            // Garbage in the extension object
                            error!("User name identity token could not be decoded");
                            Err(StatusCode::BadIdentityTokenInvalid)
                        }
                    }
                    ObjectId::X509IdentityToken_Encoding_DefaultBinary => {
                        // X509 certs
                        if let Ok(token) = user_identity_token.decode_inner::<X509IdentityToken>(&decoding_limits) {
                            self.authenticate_x509_identity_token(&config, endpoint, &token, &request.user_token_signature, &self.server_certificate, server_nonce)
                        } else {
                            // Garbage in the extension object
                            error!("X509 identity token could not be decoded");
                            Err(StatusCode::BadIdentityTokenInvalid)
                        }
                    }
                    _ => {
                        error!("User identity token type {:?} is unsupported", object_id);
                        Err(StatusCode::BadIdentityTokenInvalid)
                    }
                }
            } else {
                error!("Cannot read user identity token");
                Err(StatusCode::BadIdentityTokenInvalid)
            }
        } else {
            error!("Cannot find endpoint that matches path \"{}\", security policy {:?}, and security mode {:?}", endpoint_url, security_policy, security_mode);
            Err(StatusCode::BadTcpEndpointUrlInvalid)
        }
    }

    pub fn set_register_nodes_callbacks(&mut self, register_nodes_callback: Box<RegisterNodes + Send + Sync>, unregister_nodes_callback: Box<UnregisterNodes + Send + Sync>) {
        self.register_nodes_callback = Some(register_nodes_callback);
        self.unregister_nodes_callback = Some(unregister_nodes_callback);
    }

    /// Authenticates an anonymous token, i.e. does the endpoint support anonymous access or not
    fn authenticate_anonymous_token(endpoint: &ServerEndpoint, token: &AnonymousIdentityToken) -> Result<String, StatusCode> {
        if token.policy_id.as_ref() != POLICY_ID_ANONYMOUS {
            error!("Token doesn't possess the correct policy id");
            Err(StatusCode::BadIdentityTokenRejected)
        } else if !endpoint.supports_anonymous() {
            error!("Endpoint \"{}\" does not support anonymous authentication", endpoint.path);
            Err(StatusCode::BadIdentityTokenRejected)
        } else {
            debug!("Anonymous identity is authenticated");
            Ok(String::from(crate::config::ANONYMOUS_USER_TOKEN_ID))
        }
    }

    /// Authenticates the username identity token with the supplied endpoint. The function returns the user token identifier
    /// that matches the identity token.
    fn authenticate_username_identity_token(&self, config: &ServerConfig, endpoint: &ServerEndpoint, token: &UserNameIdentityToken, server_key: &Option<PrivateKey>, server_nonce: &ByteString) -> Result<String, StatusCode> {
        if !endpoint.supports_user_pass(&config.user_tokens) {
            error!("Endpoint doesn't support username password tokens");
            Err(StatusCode::BadIdentityTokenRejected)
        } else if token.policy_id != Self::user_pass_security_policy_id(endpoint) {
            error!("Token doesn't possess the correct policy id");
            Err(StatusCode::BadIdentityTokenRejected)
        } else if token.user_name.is_null() {
            error!("User identify token supplies no user name");
            Err(StatusCode::BadIdentityTokenInvalid)
        } else {
            debug!("policy id = {}, encryption algorithm = {}", token.policy_id.as_ref(), token.encryption_algorithm.as_ref());
            let token_password = if !token.encryption_algorithm.is_null() {
                if let Some(ref server_key) = server_key {
                    user_identity::decrypt_user_identity_token_password(&token, server_nonce.as_ref(), server_key)?
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
                    if server_user_token.is_user_pass() && &server_user_token.user == token.user_name.as_ref() {
                        // test for empty password
                        let valid = if server_user_token.pass.is_none() {
                            // Empty password for user
                            token_password.is_empty()
                        } else {
                            // Password compared as UTF-8 bytes
                            let server_password = server_user_token.pass.as_ref().unwrap().as_bytes();
                            server_password == token_password.as_bytes()
                        };
                        if !valid {
                            error!("Cannot authenticate \"{}\", password is invalid", server_user_token.user);
                            return Err(StatusCode::BadIdentityTokenRejected);
                        } else {
                            return Ok(user_token_id.clone());
                        }
                    }
                }
            }
            error!("Cannot authenticate \"{}\", user not found for endpoint", token.user_name);
            Err(StatusCode::BadIdentityTokenRejected)
        }
    }

    /// Authenticate the x509 token against the endpoint. The function returns the user token identifier
    /// that matches the identity token.
    fn authenticate_x509_identity_token(&self, config: &ServerConfig, endpoint: &ServerEndpoint, token: &X509IdentityToken, user_token_signature: &SignatureData, server_certificate: &Option<X509>, server_nonce: &ByteString) -> Result<String, StatusCode> {
        if !endpoint.supports_x509(&config.user_tokens) {
            error!("Endpoint doesn't support x509 tokens");
            Err(StatusCode::BadIdentityTokenRejected)
        } else if token.policy_id.as_ref() != POLICY_ID_X509 {
            error!("Token doesn't possess the correct policy id");
            Err(StatusCode::BadIdentityTokenRejected)
        } else {
            let result = match server_certificate {
                Some(ref server_certificate) => {
                    let security_policy = endpoint.security_policy();
                    // The security policy has to be something that can encrypt
                    match security_policy {
                        SecurityPolicy::Unknown | SecurityPolicy::None => Err(StatusCode::BadIdentityTokenInvalid),
                        security_policy => {
                            // Verify token
                            user_identity::verify_x509_identity_token(token, user_token_signature, security_policy, server_certificate, server_nonce.as_ref())
                        }
                    }
                }
                None => {
                    Err(StatusCode::BadIdentityTokenInvalid)
                }
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
}
