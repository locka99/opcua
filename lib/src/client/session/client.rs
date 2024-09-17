use std::{path::PathBuf, str::FromStr, sync::Arc};

use chrono::Duration;
use tokio::{pin, select};

use crate::{
    client::{
        retry::SessionRetryPolicy,
        transport::{tcp::TransportConfiguration, TransportPollResult},
        AsyncSecureChannel, ClientConfig, ClientEndpoint, IdentityToken, ANONYMOUS_USER_TOKEN_ID,
    },
    core::{
        comms::url::{
            hostname_from_url, is_opc_ua_binary_url, is_valid_opc_ua_url,
            server_url_from_endpoint_url, url_matches_except_host, url_with_replaced_hostname,
        },
        config::Config,
        supported_message::SupportedMessage,
    },
    crypto::{CertificateStore, SecurityPolicy},
    sync::RwLock,
    types::{
        ApplicationDescription, DecodingOptions, EndpointDescription, FindServersRequest,
        GetEndpointsRequest, MessageSecurityMode, RegisterServerRequest, RegisteredServer,
        StatusCode,
    },
};

use super::{
    process_service_result, process_unexpected_response, Session, SessionEventLoop, SessionInfo,
};

pub struct Client {
    /// Client configuration
    config: ClientConfig,
    /// Certificate store is where certificates go.
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// The session retry policy for new sessions
    session_retry_policy: SessionRetryPolicy,
}

impl Client {
    /// Create a new client from config.
    ///
    /// Note that this does not make any connection to the server.
    ///
    /// # Arguments
    ///
    /// * `config` - Client configuration object.
    pub fn new(config: ClientConfig) -> Self {
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

        // The session retry policy dictates how many times to retry if connection to the server goes down
        // and on what interval

        let session_retry_policy = SessionRetryPolicy::new(
            config.session_retry_max,
            if config.session_retry_limit < 0 {
                None
            } else {
                Some(config.session_retry_limit as u32)
            },
            config.session_retry_initial,
        );

        Self {
            config,
            session_retry_policy,
            certificate_store: Arc::new(RwLock::new(certificate_store)),
        }
    }

    /// Connects to a named endpoint that you have defined in the `ClientConfig`
    /// and creates a [`Session`] for that endpoint. Note that `GetEndpoints` is first
    /// called on the server and it is expected to support the endpoint you intend to connect to.
    ///
    /// # Returns
    ///
    /// * `Ok((Arc<AsyncSession>, SessionEventLoop))` - Session and event loop.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn connect_to_endpoint_id(
        &mut self,
        endpoint_id: Option<&str>,
    ) -> Result<(Arc<Session>, SessionEventLoop), StatusCode> {
        // Ask the server associated with the default endpoint for its list of endpoints
        let endpoints = match self.get_server_endpoints().await {
            Err(status_code) => {
                error!("Cannot get endpoints for server, error - {}", status_code);
                return Err(status_code);
            }
            Ok(endpoints) => endpoints,
        };

        debug!("server has these endpoints:");
        endpoints.iter().for_each(|e| {
            debug!(
                "  {} - {:?} / {:?}",
                e.endpoint_url,
                SecurityPolicy::from_str(e.security_policy_uri.as_ref()).unwrap(),
                e.security_mode
            )
        });

        // Create a session to an endpoint. If an endpoint id is specified use that
        if let Some(endpoint_id) = endpoint_id {
            self.new_session_from_id(endpoint_id, &endpoints)
        } else {
            self.new_session(&endpoints)
        }
        .map_err(|_| StatusCode::BadConfigurationError)
    }

    /// Connects to an ad-hoc server endpoint description.
    ///
    /// This function returns both a reference to the session, and a `SessionEventLoop`. You must run and
    /// poll the event loop in order to actually establish a connection.
    ///
    /// This method will not attempt to create a session on the server, that will only happen once you start polling
    /// the session event loop.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Discovery endpoint, the client will first connect to this in order to get a list of the
    ///   available endpoints on the server.
    /// * `user_identity_token` - Identity token to use for authentication.
    ///
    /// # Returns
    ///
    /// * `Ok((Arc<AsyncSession>, SessionEventLoop))` - Session and event loop.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn new_session_from_endpoint(
        &mut self,
        endpoint: impl Into<EndpointDescription>,
        user_identity_token: IdentityToken,
    ) -> Result<(Arc<Session>, SessionEventLoop), StatusCode> {
        let endpoint = endpoint.into();

        // Get the server endpoints
        let server_url = endpoint.endpoint_url.as_ref();

        let server_endpoints = self
            .get_server_endpoints_from_url(server_url)
            .await
            .map_err(|status_code| {
                error!("Cannot get endpoints for server, error - {}", status_code);
                status_code
            })?;

        // Find the server endpoint that matches the one desired
        let security_policy = SecurityPolicy::from_str(endpoint.security_policy_uri.as_ref())
            .map_err(|_| StatusCode::BadSecurityPolicyRejected)?;
        let server_endpoint = Self::find_matching_endpoint(
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

        Ok(self
            .new_session_from_info(SessionInfo {
                endpoint: server_endpoint,
                user_identity_token,
                preferred_locales: Vec::new(),
            })
            .unwrap())
    }

    /// Connects to an a server directly using provided [`SessionInfo`].
    ///
    /// This function returns both a reference to the session, and a `SessionEventLoop`. You must run and
    /// poll the event loop in order to actually establish a connection.
    ///
    /// This method will not attempt to create a session on the server, that will only happen once you start polling
    /// the session event loop.
    ///
    /// # Arguments
    ///
    /// * `session_info` - Session info for creating a new session.
    ///
    /// # Returns
    ///
    /// * `Ok((Arc<AsyncSession>, SessionEventLoop))` - Session and event loop.
    /// * `Err(String)` - Endpoint is invalid.
    ///
    pub fn new_session_from_info(
        &mut self,
        session_info: impl Into<SessionInfo>,
    ) -> Result<(Arc<Session>, SessionEventLoop), String> {
        let session_info = session_info.into();
        if !is_opc_ua_binary_url(session_info.endpoint.endpoint_url.as_ref()) {
            Err(format!(
                "Endpoint url {}, is not a valid / supported url",
                session_info.endpoint.endpoint_url
            ))
        } else {
            Ok(Session::new(
                self.certificate_store.clone(),
                session_info,
                self.config.session_name.clone().into(),
                self.config.application_description(),
                self.session_retry_policy.clone(),
                self.decoding_options(),
                &self.config,
            ))
        }
    }

    /// Creates a new [`AsyncSession`] using the default endpoint specified in the config. If
    /// there is no default, or the endpoint does not exist, this function will return an error
    ///
    /// This function returns both a reference to the session, and a `SessionEventLoop`. You must run and
    /// poll the event loop in order to actually establish a connection.
    ///
    /// This method will not attempt to create a session on the server, that will only happen once you start polling
    /// the session event loop.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - A list of [`EndpointDescription`] containing the endpoints available on the server.
    ///
    /// # Returns
    ///
    /// * `Ok((Arc<AsyncSession>, SessionEventLoop))` - Session and event loop.
    /// * `Err(String)` - Endpoint is invalid.
    ///
    pub fn new_session(
        &mut self,
        endpoints: &[EndpointDescription],
    ) -> Result<(Arc<Session>, SessionEventLoop), String> {
        let endpoint = self.default_endpoint()?;
        let session_info = self.session_info_for_endpoint(&endpoint, endpoints)?;
        self.new_session_from_info(session_info)
    }

    /// Creates a new [`AsyncSession`] using the named endpoint id. If there is no
    /// endpoint of that id in the config, this function will return an error
    ///
    /// This function returns both a reference to the session, and a `SessionEventLoop`. You must run and
    /// poll the event loop in order to actually establish a connection.
    ///
    /// This method will not attempt to create a session on the server, that will only happen once you start polling
    /// the session event loop.
    ///
    /// # Arguments
    ///
    /// * `endpoint_id` - ID matching an endpoint defined in config.
    /// * `endpoints` - List of endpoints available on the server.
    ///
    pub fn new_session_from_id(
        &mut self,
        endpoint_id: impl Into<String>,
        endpoints: &[EndpointDescription],
    ) -> Result<(Arc<Session>, SessionEventLoop), String> {
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
        let session_info = self.session_info_for_endpoint(&endpoint, endpoints)?;
        self.new_session_from_info(session_info)
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

    /// Create a secure channel using the provided [`SessionInfo`].
    ///
    /// This is used when creating temporary connections to the server, when creating a session,
    /// [`AsyncSession`] manages its own channel.
    fn channel_from_session_info(&self, session_info: SessionInfo) -> AsyncSecureChannel {
        AsyncSecureChannel::new(
            self.certificate_store.clone(),
            session_info,
            self.session_retry_policy.clone(),
            self.decoding_options(),
            self.config.performance.ignore_clock_skew,
            Arc::default(),
            TransportConfiguration {
                max_pending_incoming: 5,
                max_inflight: self.config.performance.max_inflight_messages,
                send_buffer_size: self.config.decoding_options.max_chunk_size,
                recv_buffer_size: self.config.decoding_options.max_incoming_chunk_size,
                max_message_size: self.config.decoding_options.max_message_size,
                max_chunk_count: self.config.decoding_options.max_chunk_count,
            },
        )
    }

    /// Returns an identity token corresponding to the matching user in the configuration. Or None
    /// if there is no matching token.
    fn client_identity_token(&self, user_token_id: impl Into<String>) -> Option<IdentityToken> {
        let user_token_id = user_token_id.into();
        if user_token_id == ANONYMOUS_USER_TOKEN_ID {
            Some(IdentityToken::Anonymous)
        } else {
            let token = self.config.user_tokens.get(&user_token_id)?;

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
        }
    }

    /// Gets the [`ClientEndpoint`] information for the default endpoint, as defined
    /// by the configuration. If there is no default endpoint, this function will return an error.
    ///
    /// # Returns
    ///
    /// * `Ok(ClientEndpoint)` - The default endpoint set in config.
    /// * `Err(String)` - No default endpoint could be found.
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

    /// Get the list of endpoints for the server at the configured default endpoint.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<EndpointDescription>)` - A list of the available endpoints on the server.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    pub async fn get_server_endpoints(&self) -> Result<Vec<EndpointDescription>, StatusCode> {
        if let Ok(default_endpoint) = self.default_endpoint() {
            if let Ok(server_url) = server_url_from_endpoint_url(&default_endpoint.url) {
                self.get_server_endpoints_from_url(server_url).await
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

    async fn get_server_endpoints_inner(
        &self,
        endpoint: &EndpointDescription,
        channel: &AsyncSecureChannel,
    ) -> Result<Vec<EndpointDescription>, StatusCode> {
        let request = GetEndpointsRequest {
            request_header: channel.make_request_header(self.config.request_timeout),
            endpoint_url: endpoint.endpoint_url.clone(),
            locale_ids: None,
            profile_uris: None,
        };
        // Send the message and wait for a response.
        let response = channel.send(request, self.config.request_timeout).await?;
        if let SupportedMessage::GetEndpointsResponse(response) = response {
            process_service_result(&response.response_header)?;
            match response.endpoints {
                None => Ok(Vec::new()),
                Some(endpoints) => Ok(endpoints),
            }
        } else {
            Err(process_unexpected_response(response))
        }
    }

    /// Get the list of endpoints for the server at the given URL.
    ///
    /// # Arguments
    ///
    /// * `server_url` - URL of the discovery server to get endpoints from.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<EndpointDescription>)` - A list of the available endpoints on the server.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    pub async fn get_server_endpoints_from_url(
        &self,
        server_url: impl Into<String>,
    ) -> Result<Vec<EndpointDescription>, StatusCode> {
        let server_url = server_url.into();
        if !is_opc_ua_binary_url(&server_url) {
            Err(StatusCode::BadTcpEndpointUrlInvalid)
        } else {
            let preferred_locales = Vec::new();
            // Most of these fields mean nothing when getting endpoints
            let endpoint = EndpointDescription::from(server_url.as_ref());
            let session_info = SessionInfo {
                endpoint: endpoint.clone(),
                user_identity_token: IdentityToken::Anonymous,
                preferred_locales,
            };
            let channel = self.channel_from_session_info(session_info);

            let mut evt_loop = channel.connect().await?;

            let send_fut = self.get_server_endpoints_inner(&endpoint, &channel);
            pin!(send_fut);

            let res = loop {
                select! {
                    r = evt_loop.poll() => {
                        if let TransportPollResult::Closed(e) = r {
                            return Err(e);
                        }
                    },
                    res = &mut send_fut => break res
                }
            };

            channel.close_channel().await;

            loop {
                if matches!(evt_loop.poll().await, TransportPollResult::Closed(_)) {
                    break;
                }
            }

            res
        }
    }

    async fn find_servers_inner(
        &self,
        endpoint_url: String,
        channel: &AsyncSecureChannel,
    ) -> Result<Vec<ApplicationDescription>, StatusCode> {
        let request = FindServersRequest {
            request_header: channel.make_request_header(self.config.request_timeout),
            endpoint_url: endpoint_url.into(),
            locale_ids: None,
            server_uris: None,
        };

        let response = channel.send(request, self.config.request_timeout).await?;
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

    /// Connects to a discovery server and asks the server for a list of
    /// available servers' [`ApplicationDescription`].
    ///
    /// # Arguments
    ///
    /// * `discovery_endpoint_url` - Discovery endpoint to connect to.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ApplicationDescription>)` - List of descriptions for servers known to the discovery server.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    pub async fn find_servers(
        &mut self,
        discovery_endpoint_url: impl Into<String>,
    ) -> Result<Vec<ApplicationDescription>, StatusCode> {
        let discovery_endpoint_url = discovery_endpoint_url.into();
        debug!("find_servers, {}", discovery_endpoint_url);
        let endpoint = EndpointDescription::from(discovery_endpoint_url.as_ref());
        let session_info = SessionInfo {
            endpoint: endpoint.clone(),
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales: Vec::new(),
        };
        let channel = self.channel_from_session_info(session_info);

        let mut evt_loop = channel.connect().await?;

        let send_fut = self.find_servers_inner(discovery_endpoint_url, &channel);
        pin!(send_fut);

        let res = loop {
            select! {
                r = evt_loop.poll() => {
                    if let TransportPollResult::Closed(e) = r {
                        return Err(e);
                    }
                },
                res = &mut send_fut => break res
            }
        };

        channel.close_channel().await;

        loop {
            if matches!(evt_loop.poll().await, TransportPollResult::Closed(_)) {
                break;
            }
        }

        res
    }

    /// Find an endpoint supplied from the list of endpoints that matches the input criteria.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - List of available endpoints on the server.
    /// * `endpoint_url` - Given endpoint URL.
    /// * `security_policy` - Required security policy.
    /// * `security_mode` - Required security mode.
    ///
    /// # Returns
    ///
    /// * `Some(EndpointDescription)` - Validated endpoint.
    /// * `None` - No matching endpoint was found.
    pub fn find_matching_endpoint(
        endpoints: &[EndpointDescription],
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> Option<EndpointDescription> {
        if security_policy == SecurityPolicy::Unknown {
            panic!("Cannot match against unknown security policy");
        }

        let mut matching_endpoint = endpoints
            .iter()
            .find(|e| {
                // Endpoint matches if the security mode, policy and url match
                security_mode == e.security_mode
                    && security_policy == SecurityPolicy::from_uri(e.security_policy_uri.as_ref())
                    && url_matches_except_host(endpoint_url, e.endpoint_url.as_ref())
            })
            .cloned()?;

        let hostname = hostname_from_url(endpoint_url).ok()?;
        let new_endpoint_url =
            url_with_replaced_hostname(matching_endpoint.endpoint_url.as_ref(), &hostname).ok()?;

        // Issue #16, #17 - the server may advertise an endpoint whose hostname is inaccessible
        // to the client so substitute the advertised hostname with the one the client supplied.
        matching_endpoint.endpoint_url = new_endpoint_url.into();
        Some(matching_endpoint)
    }

    /// Determine if we recognize the security of this endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Endpoint to check.
    ///
    /// # Returns
    ///
    /// * `bool` - `true` if the endpoint is supported.
    pub fn is_supported_endpoint(&self, endpoint: &EndpointDescription) -> bool {
        if let Ok(security_policy) = SecurityPolicy::from_str(endpoint.security_policy_uri.as_ref())
        {
            !matches!(security_policy, SecurityPolicy::Unknown)
        } else {
            false
        }
    }

    async fn register_server_inner(
        &self,
        server: RegisteredServer,
        channel: &AsyncSecureChannel,
    ) -> Result<(), StatusCode> {
        let request = RegisterServerRequest {
            request_header: channel.make_request_header(self.config.request_timeout),
            server,
        };
        let response = channel.send(request, self.config.request_timeout).await?;
        if let SupportedMessage::RegisterServerResponse(response) = response {
            process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(process_unexpected_response(response))
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
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn register_server(
        &mut self,
        discovery_endpoint_url: impl Into<String>,
        server: RegisteredServer,
    ) -> Result<(), StatusCode> {
        let discovery_endpoint_url = discovery_endpoint_url.into();
        if !is_valid_opc_ua_url(&discovery_endpoint_url) {
            error!(
                "Discovery endpoint url \"{}\" is not a valid OPC UA url",
                discovery_endpoint_url
            );
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        }

        debug!("register_server({}, {:?}", discovery_endpoint_url, server);
        let endpoints = self
            .get_server_endpoints_from_url(discovery_endpoint_url.clone())
            .await?;
        if endpoints.is_empty() {
            return Err(StatusCode::BadUnexpectedError);
        }

        let Some(endpoint) = endpoints
            .iter()
            .filter(|e| self.is_supported_endpoint(*e))
            .max_by(|a, b| a.security_level.cmp(&b.security_level))
        else {
            error!("Cannot find an endpoint that we call register server on");
            return Err(StatusCode::BadUnexpectedError);
        };

        debug!(
            "Registering this server via discovery endpoint {:?}",
            endpoint
        );

        let session_info = SessionInfo {
            endpoint: endpoint.clone(),
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales: Vec::new(),
        };
        let channel = self.channel_from_session_info(session_info);

        let mut evt_loop = channel.connect().await?;

        let send_fut = self.register_server_inner(server, &channel);
        pin!(send_fut);

        let res = loop {
            select! {
                r = evt_loop.poll() => {
                    if let TransportPollResult::Closed(e) = r {
                        return Err(e);
                    }
                },
                res = &mut send_fut => break res
            }
        };

        channel.close_channel().await;

        loop {
            if matches!(evt_loop.poll().await, TransportPollResult::Closed(_)) {
                break;
            }
        }

        res
    }
}
