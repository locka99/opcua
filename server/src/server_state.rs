//! The server module defines types related to the server, it's current running state
//! and end point information.

use std::sync::{Arc, Mutex};

use opcua_types::*;
use opcua_types::profiles;

use opcua_core::prelude::*;

use address_space::types::AddressSpace;
use config::{ServerEndpoint, ServerConfig};

#[derive(Clone)]
/// Structure that captures diagnostics information for the server
pub struct ServerDiagnostics {}

impl ServerDiagnostics {
    pub fn new() -> ServerDiagnostics {
        ServerDiagnostics {}
    }
}

/// Server state is any state associated with the server as a whole that individual sessions might
/// be interested in. That includes configuration info, address space etc.
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
    pub config: Arc<Mutex<ServerConfig>>,
    /// Certificate store for certs
    pub certificate_store: Arc<Mutex<CertificateStore>>,
    /// Server public certificate read from config location or null if there is none
    pub server_certificate: Option<X509>,
    /// Server private key pair
    pub server_pkey: Option<PKey>,
    /// The address space
    pub address_space: Arc<Mutex<AddressSpace>>,
    /// The next subscription id - subscriptions are shared across the whole server. Initial value
    /// is a random u32.
    pub last_subscription_id: UInt32,
    /// Maximum number of subscriptions per session, 0 means no limit (danger)
    pub max_subscriptions: usize,
    /// Minimum publishing interval
    pub min_publishing_interval: Duration,
    /// Maxmimum keep alive count
    pub max_keep_alive_count: UInt32,
    /// Sets the abort flag that terminates the associated server
    pub abort: bool,
    /// Diagnostic information
    pub diagnostics: ServerDiagnostics,
}

impl ServerState {
    pub fn endpoints(&self, transport_profile_uris: Option<Vec<UAString>>) -> Option<Vec<EndpointDescription>> {
        // Filter endpoints based on profile_uris
        debug!("Endpoints requested {:?}", transport_profile_uris);
        if let Some(transport_profile_uris) = transport_profile_uris {
            if !transport_profile_uris.is_empty() {
                // As we only support binary transport, the result is None if the supplied profile_uris does not contain that profile
                let found_binary_transport = transport_profile_uris.iter().find(|profile_uri| {
                    profile_uri.as_ref() == profiles::TRANSPORT_PROFILE_URI_BINARY
                });
                if found_binary_transport.is_none() {
                    error!("Client wants to connect with a non binary transport {:#?}", transport_profile_uris);
                    return None;
                }
            }
        }
        // Return the endpoints
        let config = self.config.lock().unwrap();
        Some(config.endpoints.iter().map(|(_, e)| self.new_endpoint_description(&config, e, true)).collect())
    }

    pub fn endpoint_exists(&self, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> bool {
        let config = self.config.lock().unwrap();
        config.find_endpoint(endpoint_url, security_policy, security_mode).is_some()
    }

    /// Make matching endpoint descriptions for the specified url.
    /// If none match then None will be passed, therefore if Some is returned it will be guaranteed
    /// to contain at least one result.
    pub fn new_endpoint_descriptions(&self, endpoint_url: &str) -> Option<Vec<EndpointDescription>> {
        debug!("find_endpoint, url = {}", endpoint_url);
        let config = self.config.lock().unwrap();
        let base_endpoint_url = config.base_endpoint_url();
        let endpoints: Vec<EndpointDescription> = config.endpoints.iter().filter(|&(_, e)| {
            // Test end point's security_policy_uri and matching url
            if let Ok(result) = url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url) {
                result
            } else {
                false
            }
        }).map(|(_, e)| self.new_endpoint_description(&config, e, false)).collect();
        if endpoints.is_empty() { None } else { Some(endpoints) }
    }

    /// Constructs a new endpoint description using the server's info and that in an Endpoint
    fn new_endpoint_description(&self, config: &ServerConfig, endpoint: &ServerEndpoint, all_fields: bool) -> EndpointDescription {
        let base_endpoint_url = config.base_endpoint_url();

        let mut user_identity_tokens = Vec::with_capacity(2);
        if endpoint.supports_anonymous() {
            user_identity_tokens.push(UserTokenPolicy::new_anonymous());
        }
        if !endpoint.user_token_ids.is_empty() {
            user_identity_tokens.push(UserTokenPolicy::new_user_pass());
        }

        // CreateSession doesn't need all the endpoint description
        // and docs say not to bother sending the server and server
        // certificate info.
        let (server, server_certificate) = if all_fields {
            (ApplicationDescription {
                application_uri: self.application_uri.clone(),
                product_uri: self.product_uri.clone(),
                application_name: self.application_name.clone(),
                application_type: ApplicationType::Server,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
            }, self.server_certificate_as_byte_string())
        } else {
            (ApplicationDescription {
                application_uri: UAString::null(),
                product_uri: UAString::null(),
                application_name: LocalizedText::null(),
                application_type: ApplicationType::Server,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
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
            security_level: 1,
        }
    }

    pub fn server_certificate_as_byte_string(&self) -> ByteString {
        if self.server_certificate.is_some() {
            self.server_certificate.as_ref().unwrap().as_byte_string()
        } else {
            ByteString::null()
        }
    }

    pub fn create_subscription_id(&mut self) -> UInt32 {
        self.last_subscription_id += 1;
        self.last_subscription_id
    }

    /// Authenticates access to an endpoint. The endpoint is described by its path, policy, mode and
    /// the token is supplied in an extension object that must be extracted and authenticated.
    ///
    /// It is possible that the endpoint does not exist, or that the token is invalid / unsupported
    /// or that the token cannot be used with the end point. The return codes reflect the responses
    /// that ActivateSession would expect from a service call.
    pub fn authenticate_endpoint(&self, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode, user_identity_token: &ExtensionObject) -> StatusCode {
        // Get security from endpoint url
        let config = self.config.lock().unwrap();
        if let Some(endpoint) = config.find_endpoint(endpoint_url, security_policy, security_mode) {
            // Now validate the user identity token
            if user_identity_token.is_null() || user_identity_token.is_empty() {
                // Empty tokens are treated as anonymous
                Self::authenticate_anonymous_token(endpoint)
            } else {
                // Read the token out from the extension object
                if let Ok(object_id) = user_identity_token.node_id.as_object_id() {
                    match object_id {
                        ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary => {
                            // Anonymous
                            Self::authenticate_anonymous_token(endpoint)
                        }
                        ObjectId::UserNameIdentityToken_Encoding_DefaultBinary => {
                            // Username / password
                            let result = user_identity_token.decode_inner::<UserNameIdentityToken>();
                            if let Ok(token) = result {
                                if self.authenticate_username_identity_token(&config, endpoint, &token) {
                                    debug!("Username identity token is authenticated");
                                    GOOD
                                } else {
                                    error!("User \"{}\" could not be authenticated", token.user_name);
                                    BAD_IDENTITY_TOKEN_REJECTED
                                }
                            } else {
                                // Garbage in the extension object
                                error!("User name identity token could not be decoded");
                                BAD_IDENTITY_TOKEN_REJECTED
                            }
                        }
                        _ => {
                            error!("User identity token type {:?} is not supported", object_id);
                            BAD_IDENTITY_TOKEN_REJECTED
                        }
                    }
                } else {
                    error!("Cannot read user identity token");
                    BAD_IDENTITY_TOKEN_REJECTED
                }
            }
        } else {
            error!("Cannot find endpoint that matches path \"{}\", security policy {:?}, and security mode {:?}", endpoint_url, security_policy, security_mode);
            BAD_TCP_ENDPOINT_URL_INVALID
        }
    }

    /// Authenticates an anonymous token, i.e. does the endpoint support anonymous access or not
    fn authenticate_anonymous_token(endpoint: &ServerEndpoint) -> StatusCode {
        if endpoint.supports_anonymous() {
            debug!("Anonymous identity is authenticated");
            GOOD
        } else {
            error!("Endpoint \"{}\" does not support anonymous authentication", endpoint.path);
            BAD_IDENTITY_TOKEN_REJECTED
        }
    }

    /// Authenticates the username identity token with the supplied endpoint
    fn authenticate_username_identity_token(&self, config: &ServerConfig, endpoint: &ServerEndpoint, token: &UserNameIdentityToken) -> bool {
        // Iterate ids in endpoint
        if token.user_name.is_null() {
            error!("User identify token supplies no user name");
            false
        } else {

            // TODO the token specifies a security policy and an encryption algorithm that
            // may be used to decrypt the password. At present password is plaintext only.

            for user_token_id in &endpoint.user_token_ids {
                if let Some(server_user_token) = config.user_tokens.get(user_token_id) {
                    if &server_user_token.user == token.user_name.as_ref() {
                        // test for empty password
                        let result = if server_user_token.pass.is_none() {
                            // Empty password for user
                            token.authenticate(&server_user_token.user, b"")
                        } else {
                            // Password compared as UTF-8 bytes
                            let password = server_user_token.pass.as_ref().unwrap().as_bytes();
                            token.authenticate(&server_user_token.user, password)
                        };
                        let valid = result.is_ok();
                        if !valid {
                            error!("Cannot authenticate \"{}\", password is invalid", server_user_token.user);
                        }
                        return valid;
                    }
                }
            }
            error!("Cannot authenticate \"{}\", user not found for endpoint", token.user_name);
            false
        }
    }
}
