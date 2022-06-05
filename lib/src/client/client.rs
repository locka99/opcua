// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Client setup and session creation.

use std::{path::PathBuf, str::FromStr, sync::Arc};

use chrono::Duration;

use super::{
    config::{ClientConfig, ClientEndpoint, ANONYMOUS_USER_TOKEN_ID},
    session::{
        services::*,
        session::{Session, SessionInfo},
    },
    session_retry_policy::SessionRetryPolicy,
};

use crate::{
    core::{
        comms::url::{
            hostname_from_url, is_opc_ua_binary_url, is_valid_opc_ua_url,
            server_url_from_endpoint_url, url_matches_except_host, url_with_replaced_hostname,
        },
        config::Config,
    },
    crypto::{CertificateStore, SecurityPolicy},
    sync::RwLock,
    trace_read_lock,
    types::{
        service_types::{ApplicationDescription, EndpointDescription, RegisteredServer},
        status_code::StatusCode,
        DecodingOptions, MessageSecurityMode,
    },
};

#[derive(Debug, Clone)]
pub enum IdentityToken {
    /// Anonymous identity token
    Anonymous,
    /// User name and a password
    UserName(String, String),
    /// X5090 cert - a path to the cert.der, and private.pem
    X509(PathBuf, PathBuf),
}

/// The `Client` defines a connection that can be used to to get end points or establish
/// one or more sessions with an OPC UA server. It is constructed via a [`ClientBuilder`] or
/// from a described configuration [`ClientConfig`] that could be deserialized from file.
///
/// You have a couple of choices when creating a client that connects to a server depending on whether
/// you know the endpoints up front.
///
/// 1. Define all the endpoints you expect to connect with via your builder / config and then
///    use `connect_to_endpoint_id()` to  connect to one of them by its id. This option assumes that your
///    client and the server it connects to are describing the same endpoints. It will not work if the server describes different endpoints
///    than the one in your config.
///
/// 2. Define no endpoints and then call `connect_to_endpoint()` with an ad hoc endpoint description.
///    This is the suitable choice if your client can connect to a multitude of servers without
///    advance description of their endpoints.
///
/// [`ClientConfig`]: ../config/struct.ClientConfig.html
/// [`ClientBuilder`]: ../builder/struct.ClientBuilder.html
///
pub struct Client {
    /// Client configuration
    config: ClientConfig,
    /// Certificate store is where certificates go.
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// The session retry policy for new sessions
    session_retry_policy: SessionRetryPolicy,
}

impl Drop for Client {
    fn drop(&mut self) {
        // TODO - this causes panics on unwrap - have to figure the reason out
        //        for session in self.sessions.iter_mut() {
        //            // Disconnect
        //            let mut session = trace_write_lock!(session.session);
        //            if session.is_connected() {
        //                session.disconnect()
        //            }
        //        }
    }
}

impl From<ClientConfig> for Client {
    fn from(config: ClientConfig) -> Client {
        Client::new(config)
    }
}

impl Client {
    /// Creates a new [`Client`] instance from a [`ClientConfig`]. The configuration
    /// defines the behaviour of the new client, which endpoints it recognizes, where it stores
    /// certificates etc.
    ///
    /// A [`Client`] can be made directly or by using a [`ClientBuilder`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::PathBuf;
    /// use opcua::client::prelude::*;
    ///
    /// fn main() {
    ///     let mut client = Client::new(ClientConfig::load(&PathBuf::from("./myclient.conf")).unwrap());
    ///     if let Ok(session) = client.connect_to_endpoint_id(None) {
    ///         // ..
    ///     }
    /// }
    /// ```
    ///
    /// [`Client`]: ./struct.Client.html
    /// [`ClientConfig`]: ../config/struct.ClientConfig.html
    /// [`ClientBuilder`]: ../config/struct.ClientBuilder.html
    ///
    pub fn new(config: ClientConfig) -> Client {
        let application_description = if config.create_sample_keypair {
            Some(config.application_description())
        } else {
            None
        };

        let (mut certificate_store, client_certificate, client_pkey) =
            CertificateStore::new_with_x509_data(
                &config.pki_dir,
                false,
                config.certificate_path.as_deref(),
                config.private_key_path.as_deref(),
                application_description,
            );
        if client_certificate.is_none() || client_pkey.is_none() {
            error!("Client is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.")
        }

        // Clients may choose to skip additional server certificate validations
        certificate_store.set_skip_verify_certs(!config.verify_server_certs);

        // Clients may choose to auto trust servers to save some messing around with rejected certs
        certificate_store.set_trust_unknown_certs(config.trust_server_certs);

        let session_timeout = config.session_timeout as f64;

        // The session retry policy dictates how many times to retry if connection to the server goes down
        // and on what interval
        let session_retry_policy = match config.session_retry_limit {
            // Try forever
            -1 => SessionRetryPolicy::infinity(session_timeout, config.session_retry_interval),
            // Never try
            0 => SessionRetryPolicy::never(session_timeout),
            // Try this many times
            session_retry_limit => SessionRetryPolicy::new(
                session_timeout,
                session_retry_limit as u32,
                config.session_retry_interval,
            ),
        };

        Client {
            config,
            session_retry_policy,
            certificate_store: Arc::new(RwLock::new(certificate_store)),
        }
    }

    /// Returns a filled OPC UA [`ApplicationDescription`] using information from the config
    ///
    /// [`ApplicationDescription`]: ../../opcua_types/service_types/application_description/struct.ApplicationDescription.html
    ///
    pub fn application_description(&self) -> ApplicationDescription {
        self.config.application_description()
    }

    /// Connects to a named endpoint that you have defined in the `ClientConfig`
    /// and creates / activates a [`Session`] for that endpoint. Note that `GetEndpoints` is first
    /// called on the server and it is expected to support the endpoint you intend to connect to.
    ///
    /// Returns with the session that has been established or an error.
    ///
    /// Important Note: The `Session` you receive from this call is protected because it is
    /// accessed by multiple internal threads. You must scope lock calls to this session object and not
    /// hold the lock for more than required.
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn connect_to_endpoint_id(
        &mut self,
        endpoint_id: Option<&str>,
    ) -> Result<Arc<RwLock<Session>>, StatusCode> {
        // Ask the server associated with the default endpoint for its list of endpoints
        let endpoints = match self.get_server_endpoints() {
            Result::Err(status_code) => {
                error!("Cannot get endpoints for server, error - {}", status_code);
                return Err(status_code);
            }
            Result::Ok(endpoints) => endpoints,
        };

        info!("Server has these endpoints:");
        endpoints.iter().for_each(|e| {
            info!(
                "  {} - {:?} / {:?}",
                e.endpoint_url,
                SecurityPolicy::from_str(e.security_policy_uri.as_ref()).unwrap(),
                e.security_mode
            )
        });

        // Create a session to an endpoint. If an endpoint id is specified use that
        let session = if let Some(endpoint_id) = endpoint_id {
            self.new_session_from_id(endpoint_id, &endpoints).unwrap()
        } else {
            self.new_session(&endpoints).unwrap()
        };

        {
            // Connect to the server
            let mut session = session.write();
            session.connect_and_activate().map_err(|err| {
                error!("Got an error while creating the default session - {}", err);
                err
            })?;
        }

        Ok(session)
    }

    /// Connects to an ad-hoc server endpoint description. and creates / activates a [`Session`] for
    /// that endpoint.
    ///
    /// Returns with the session that has been established or an error.
    ///
    /// Important Note: The `Session` you receive from this call is protected because it is
    /// accessed by multiple internal threads. You must scope lock calls to this session object and not
    /// hold the lock for more than required.
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn connect_to_endpoint<T>(
        &mut self,
        endpoint: T,
        user_identity_token: IdentityToken,
    ) -> Result<Arc<RwLock<Session>>, StatusCode>
    where
        T: Into<EndpointDescription>,
    {
        let endpoint = endpoint.into();

        // Get the server endpoints
        let server_url = endpoint.endpoint_url.as_ref();

        let server_endpoints =
            self.get_server_endpoints_from_url(server_url)
                .map_err(|status_code| {
                    error!("Cannot get endpoints for server, error - {}", status_code);
                    status_code
                })?;

        // Find the server endpoint that matches the one desired
        let security_policy = SecurityPolicy::from_str(endpoint.security_policy_uri.as_ref())
            .map_err(|_| StatusCode::BadSecurityPolicyRejected)?;
        let server_endpoint = Client::find_matching_endpoint(
            &server_endpoints,
            endpoint.endpoint_url.as_ref(),
            security_policy,
            endpoint.security_mode,
        )
        .ok_or(StatusCode::BadTcpEndpointUrlInvalid)
        .map_err(|status_code| {
            error!(
                "Cannot find matching endpoint for {}",
                endpoint.endpoint_url.as_ref()
            );
            status_code
        })?;

        // Create a session
        let session = self
            .new_session_from_info((server_endpoint, user_identity_token))
            .unwrap();

        {
            // Connect to the server
            let mut session = session.write();
            session.connect_and_activate().map_err(|err| {
                error!("Got an error while creating the default session - {}", err);
                err
            })?;
        }

        Ok(session)
    }

    /// Gets the [`ClientEndpoint`] information for the default endpoint, as defined
    /// by the configuration. If there is no default endpoint, this function will return an error.
    ///
    /// [`ClientEndpoint`]: ../config/struct.ClientEndpoint.html
    ///
    pub fn default_endpoint(&self) -> Result<ClientEndpoint, String> {
        let default_endpoint_id = self.config.default_endpoint.clone();
        if default_endpoint_id.is_empty() {
            Err("No default endpoint has been specified".to_string())
        } else if let Some(endpoint) = self.config.endpoints.get(&default_endpoint_id) {
            Ok(endpoint.clone())
        } else {
            Err(format!(
                "Cannot find default endpoint with id {}",
                default_endpoint_id
            ))
        }
    }

    /// Creates a new [`Session`] using the default endpoint specified in the config. If
    /// there is no default, or the endpoint does not exist, this function will return an error
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn new_session(
        &mut self,
        endpoints: &[EndpointDescription],
    ) -> Result<Arc<RwLock<Session>>, String> {
        let endpoint = self.default_endpoint()?;
        self.new_session_from_endpoint(&endpoint, endpoints)
    }

    /// Creates a new [`Session`] using the named endpoint id. If there is no
    /// endpoint of that id in the config, this function will return an error
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn new_session_from_id<T>(
        &mut self,
        endpoint_id: T,
        endpoints: &[EndpointDescription],
    ) -> Result<Arc<RwLock<Session>>, String>
    where
        T: Into<String>,
    {
        let endpoint_id = endpoint_id.into();
        let endpoint = {
            let endpoint = self.config.endpoints.get(&endpoint_id);
            if endpoint.is_none() {
                return Err(format!("Cannot find endpoint with id {}", endpoint_id));
            }
            // This clone is an unfortunate workaround to a lifetime issue between the borrowed
            // endpoint and the need to call the mutable new_session_from_endpoint()
            endpoint.unwrap().clone()
        };
        self.new_session_from_endpoint(&endpoint, endpoints)
    }

    /// Creates a new [`Session`] using provided client endpoint and endpoint descriptions.
    /// If the endpoint does not exist or is in error, this function will return an error.
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    fn new_session_from_endpoint(
        &mut self,
        client_endpoint: &ClientEndpoint,
        endpoints: &[EndpointDescription],
    ) -> Result<Arc<RwLock<Session>>, String> {
        let session_info = self.session_info_for_endpoint(client_endpoint, endpoints)?;
        self.new_session_from_info(session_info)
    }

    /// Creates an ad hoc new [`Session`] using the specified endpoint url, security policy and mode.
    ///
    /// This function supports anything that implements `Into<SessionInfo>`, for example `EndpointDescription`.
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn new_session_from_info<T>(
        &mut self,
        session_info: T,
    ) -> Result<Arc<RwLock<Session>>, String>
    where
        T: Into<SessionInfo>,
    {
        let session_info = session_info.into();
        if !is_opc_ua_binary_url(session_info.endpoint.endpoint_url.as_ref()) {
            Err(format!(
                "Endpoint url {}, is not a valid / supported url",
                session_info.endpoint.endpoint_url
            ))
        } else {
            let session = Arc::new(RwLock::new(Session::new(
                self.application_description(),
                self.config.session_name.clone(),
                self.certificate_store.clone(),
                session_info,
                self.session_retry_policy.clone(),
                self.decoding_options(),
                self.config.performance.ignore_clock_skew,
                self.config.performance.single_threaded_executor,
            )));
            Ok(session)
        }
    }

    /// Connects to the client's default configured endpoint asks the server for a list of
    /// [`EndpointDescription`] that it hosts. If there is an error, the function will
    /// return an error.
    ///
    /// [`EndpointDescription`]: ../../opcua_types/service_types/endpoint_description/struct.EndpointDescription.html
    ///
    pub fn get_server_endpoints(&self) -> Result<Vec<EndpointDescription>, StatusCode> {
        if let Ok(default_endpoint) = self.default_endpoint() {
            if let Ok(server_url) = server_url_from_endpoint_url(&default_endpoint.url) {
                self.get_server_endpoints_from_url(server_url)
            } else {
                error!(
                    "Cannot create a server url from the specified endpoint url {}",
                    default_endpoint.url
                );
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            error!("There is no default endpoint, so cannot get endpoints");
            Err(StatusCode::BadUnexpectedError)
        }
    }

    fn decoding_options(&self) -> DecodingOptions {
        let decoding_options = &self.config.decoding_options;
        DecodingOptions {
            max_chunk_count: decoding_options.max_chunk_count,
            max_message_size: decoding_options.max_message_size,
            max_string_length: decoding_options.max_string_length,
            max_byte_string_length: decoding_options.max_byte_string_length,
            max_array_length: decoding_options.max_array_length,
            client_offset: Duration::zero(),
            ..Default::default()
        }
    }

    /// Connects to the specified server_url with a None/None connection and asks for a list of
    /// [`EndpointDescription`] that it hosts.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use opcua::client::prelude::*;
    /// use std::path::PathBuf;
    ///
    /// fn main() {
    ///     let mut client = Client::new(ClientConfig::load(&PathBuf::from("./myclient.conf")).unwrap());
    ///     if let Ok(endpoints) = client.get_server_endpoints_from_url("opc.tcp://foo:1234") {
    ///         if let Some(endpoint) = Client::find_matching_endpoint(&endpoints, "opc.tcp://foo:1234/mypath", SecurityPolicy::None, MessageSecurityMode::None) {
    ///           //...
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// [`EndpointDescription`]: ../../opcua_types/service_types/endpoint_description/struct.EndpointDescription.html
    ///
    pub fn get_server_endpoints_from_url<T>(
        &self,
        server_url: T,
    ) -> Result<Vec<EndpointDescription>, StatusCode>
    where
        T: Into<String>,
    {
        let server_url = server_url.into();
        if !is_opc_ua_binary_url(&server_url) {
            Err(StatusCode::BadTcpEndpointUrlInvalid)
        } else {
            let preferred_locales = Vec::new();
            // Most of these fields mean nothing when getting endpoints
            let endpoint = EndpointDescription::from(server_url.as_ref());
            let session_info = SessionInfo {
                endpoint,
                user_identity_token: IdentityToken::Anonymous,
                preferred_locales,
            };
            let session = Session::new(
                self.application_description(),
                self.config.session_name.clone(),
                self.certificate_store.clone(),
                session_info,
                self.session_retry_policy.clone(),
                self.decoding_options(),
                self.config.performance.ignore_clock_skew,
                self.config.performance.single_threaded_executor,
            );
            session.connect()?;
            let result = session.get_endpoints()?;
            session.disconnect();
            Ok(result)
        }
    }

    /// Connects to a discovery server and asks the server for a list of
    /// available server [`ApplicationDescription`].
    ///
    /// [`ApplicationDescription`]: ../../opcua_types/service_types/application_description/struct.ApplicationDescription.html
    ///
    pub fn find_servers<T>(
        &mut self,
        discovery_endpoint_url: T,
    ) -> Result<Vec<ApplicationDescription>, StatusCode>
    where
        T: Into<String>,
    {
        let discovery_endpoint_url = discovery_endpoint_url.into();
        debug!("find_servers, {}", discovery_endpoint_url);
        let endpoint = EndpointDescription::from(discovery_endpoint_url.as_ref());
        let session = self.new_session_from_info(endpoint);
        if let Ok(session) = session {
            let session = trace_read_lock!(session);
            // Connect & activate the session.
            let connected = session.connect();
            if connected.is_ok() {
                // Find me some some servers
                let result = session
                    .find_servers(discovery_endpoint_url.clone())
                    .map_err(|err| {
                        error!(
                            "Cannot find servers on discovery server {} - check this error - {:?}",
                            discovery_endpoint_url, err
                        );
                        err
                    });
                session.disconnect();
                result
            } else {
                let result = connected.unwrap_err();
                error!(
                    "Cannot connect to {} - check this error - {}",
                    discovery_endpoint_url, result
                );
                Err(result)
            }
        } else {
            let result = StatusCode::BadUnexpectedError;
            error!(
                "Cannot create a sesion to {} - check if url is malformed",
                discovery_endpoint_url
            );
            Err(result)
        }
    }

    /// Called by servers that wish to register themselves with a discovery server.
    ///
    /// In this role, the server becomes the client of the discovery server, so it needs to connect
    /// as a client, query the endpoints, establish a session, register its own endpoints and then
    /// disconnect.
    ///
    /// The implementation of this function looks for the strongest endpoint of the discovery server
    /// to register itself on. That makes it possible that the discovery server may reject the
    /// connection if it does not trust the client. In that instance, it is up to the user to do
    /// whatever is required to make the discovery server trust the registering server.
    ///
    /// For example the standard OPC foundation discovery server will drop the server's cert in a
    /// `rejected/` folder on the filesystem and this cert has to be moved to a `trusted/certs/` folder.
    pub fn register_server<T>(
        &mut self,
        discovery_endpoint_url: T,
        server: RegisteredServer,
    ) -> Result<(), StatusCode>
    where
        T: Into<String>,
    {
        let discovery_endpoint_url = discovery_endpoint_url.into();
        if !is_valid_opc_ua_url(&discovery_endpoint_url) {
            error!(
                "Discovery endpoint url \"{}\" is not a valid OPC UA url",
                discovery_endpoint_url
            );
            Err(StatusCode::BadTcpEndpointUrlInvalid)
        } else {
            // Get a list of endpoints from the discovery server
            debug!("register_server({}, {:?}", discovery_endpoint_url, server);
            let endpoints = self.get_server_endpoints_from_url(discovery_endpoint_url.clone())?;
            if endpoints.is_empty() {
                Err(StatusCode::BadUnexpectedError)
            } else {
                // Now choose the strongest endpoint to register through
                if let Some(endpoint) = endpoints
                    .iter()
                    .filter(|e| self.is_supported_endpoint(*e))
                    .max_by(|a, b| a.security_level.cmp(&b.security_level))
                {
                    debug!(
                        "Registering this server via discovery endpoint {:?}",
                        endpoint
                    );
                    let session = self.new_session_from_info(endpoint.clone());
                    if let Ok(session) = session {
                        let session = trace_read_lock!(session);
                        match session.connect() {
                            Ok(_) => {
                                // Register with the server
                                let result = session.register_server(server);
                                session.disconnect();
                                result
                            }
                            Err(result) => {
                                error!(
                                    "Cannot connect to {} - check this error - {}",
                                    discovery_endpoint_url, result
                                );
                                Err(result)
                            }
                        }
                    } else {
                        error!(
                            "Cannot create a sesion to {} - check if url is malformed",
                            discovery_endpoint_url
                        );
                        Err(StatusCode::BadUnexpectedError)
                    }
                } else {
                    error!("Cannot find an endpoint that we call register server on");
                    Err(StatusCode::BadUnexpectedError)
                }
            }
        }
    }

    /// Determine if we recognize the security of this endpoint
    fn is_supported_endpoint(&self, endpoint: &EndpointDescription) -> bool {
        if let Ok(security_policy) = SecurityPolicy::from_str(endpoint.security_policy_uri.as_ref())
        {
            !matches!(security_policy, SecurityPolicy::Unknown)
        } else {
            false
        }
    }

    /// Returns an identity token corresponding to the matching user in the configuration. Or None
    /// if there is no matching token.
    fn client_identity_token<T>(&self, user_token_id: T) -> Option<IdentityToken>
    where
        T: Into<String>,
    {
        let user_token_id = user_token_id.into();
        if user_token_id == ANONYMOUS_USER_TOKEN_ID {
            Some(IdentityToken::Anonymous)
        } else if let Some(token) = self.config.user_tokens.get(&user_token_id) {
            if let Some(ref password) = token.password {
                Some(IdentityToken::UserName(
                    token.user.clone(),
                    password.clone(),
                ))
            } else if let Some(ref cert_path) = token.cert_path {
                token.private_key_path.as_ref().map(|private_key_path| {
                    IdentityToken::X509(PathBuf::from(cert_path), PathBuf::from(private_key_path))
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Find an endpoint supplied from the list of endpoints that matches the input criteria
    pub fn find_matching_endpoint(
        endpoints: &[EndpointDescription],
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> Option<EndpointDescription> {
        if security_policy == SecurityPolicy::Unknown {
            panic!("Cannot match against unknown security policy");
        }

        let matching_endpoint = endpoints
            .iter()
            .find(|e| {
                // Endpoint matches if the security mode, policy and url match
                security_mode == e.security_mode
                    && security_policy == SecurityPolicy::from_uri(e.security_policy_uri.as_ref())
                    && url_matches_except_host(endpoint_url, e.endpoint_url.as_ref())
            })
            .cloned();

        // Issue #16, #17 - the server may advertise an endpoint whose hostname is inaccessible
        // to the client so substitute the advertised hostname with the one the client supplied.
        if let Some(mut matching_endpoint) = matching_endpoint {
            if let Ok(hostname) = hostname_from_url(endpoint_url) {
                if let Ok(new_endpoint_url) =
                    url_with_replaced_hostname(matching_endpoint.endpoint_url.as_ref(), &hostname)
                {
                    matching_endpoint.endpoint_url = new_endpoint_url.into();
                    Some(matching_endpoint)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Creates a [`SessionInfo`](SessionInfo) information from the supplied client endpoint.
    fn session_info_for_endpoint(
        &self,
        client_endpoint: &ClientEndpoint,
        endpoints: &[EndpointDescription],
    ) -> Result<SessionInfo, String> {
        // Enumerate endpoints looking for matching one
        if let Ok(security_policy) = SecurityPolicy::from_str(&client_endpoint.security_policy) {
            let security_mode = MessageSecurityMode::from(client_endpoint.security_mode.as_ref());
            if security_mode != MessageSecurityMode::Invalid {
                let endpoint_url = client_endpoint.url.clone();
                // Now find a matching endpoint from those on the server
                let endpoint = Self::find_matching_endpoint(
                    endpoints,
                    &endpoint_url,
                    security_policy,
                    security_mode,
                );
                if endpoint.is_none() {
                    Err(format!("Endpoint {}, {:?} / {:?} does not match against any supplied by the server", endpoint_url, security_policy, security_mode))
                } else if let Some(user_identity_token) =
                    self.client_identity_token(client_endpoint.user_token_id.clone())
                {
                    info!(
                        "Creating a session for endpoint {}, {:?} / {:?}",
                        endpoint_url, security_policy, security_mode
                    );
                    let preferred_locales = self.config.preferred_locales.clone();
                    Ok(SessionInfo {
                        endpoint: endpoint.unwrap(),
                        user_identity_token,
                        preferred_locales,
                    })
                } else {
                    Err(format!(
                        "Endpoint {} user id cannot be found",
                        client_endpoint.user_token_id
                    ))
                }
            } else {
                Err(format!(
                    "Endpoint {} security mode {} is invalid",
                    client_endpoint.url, client_endpoint.security_mode
                ))
            }
        } else {
            Err(format!(
                "Endpoint {} security policy {} is invalid",
                client_endpoint.url, client_endpoint.security_policy
            ))
        }
    }
}
