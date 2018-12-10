//! Client setup and session creation.

use std::str::FromStr;
use std::sync::{Arc, RwLock};

use opcua_types::{ByteString, MessageSecurityMode, UAString};
use opcua_types::{is_opc_ua_binary_url, server_url_from_endpoint_url, url_matches, url_matches_except_host};
use opcua_types::service_types::{ApplicationDescription, EndpointDescription, RegisteredServer};
use opcua_types::status_code::StatusCode;

use opcua_core::crypto::{CertificateStore, PrivateKey, SecurityPolicy, X509};
use opcua_core::config::Config;

use crate::{
    config::{ANONYMOUS_USER_TOKEN_ID, ClientConfig, ClientEndpoint},
    session::{Session, SessionInfo},
};

#[derive(Debug)]
pub enum IdentityToken {
    Anonymous,
    UserName(String, String),
}

struct SessionEntry {
    session: Arc<RwLock<Session>>,
}

/// The `Client` defines a connection that can be used to to get end points or establish
/// one or more sessions with an OPC UA server. It is configured using a [`ClientConfig`] which
/// defines the server it talks to and other details such as the location of the certificate store.
///
/// [`ClientConfig`]: ../config/struct.ClientConfig.html
///
pub struct Client {
    /// Client configuration
    config: ClientConfig,
    /// A list of sessions made by the client. They are protected since a session may or may not be
    /// running on an independent thread.
    sessions: Vec<SessionEntry>,
    /// Certificate store is where certificates go.
    certificate_store: Arc<RwLock<CertificateStore>>,
}

impl Drop for Client {
    fn drop(&mut self) {
// TODO - this causes panics on unwrap - have to figure the reason out
//        for session in self.sessions.iter_mut() {
//            // Disconnect
//            let mut session = trace_write_lock_unwrap!(session.session);
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
    /// Creates a new [`Client`] instance. The application name and uri are supplied as arguments to
    /// this call and are passed to each session that connects hereafter.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use opcua_client::prelude::*;
    /// use std::path::PathBuf;
    ///
    /// fn main() {
    ///     let mut client = Client::new(ClientConfig::load(&PathBuf::from("./myclient.conf")).unwrap());
    ///     if let Ok(session) = client.connect_and_activate(None) {
    ///         // ..
    ///     }
    /// }
    /// ```
    ///
    /// [`Client`]: ./struct.Client.html
    /// [`ClientConfig`]: ../config/struct.ClientConfig.html
    ///
    pub fn new(config: ClientConfig) -> Client {
        let application_description = if config.create_sample_keypair { Some(config.application_description()) } else { None };

        let (mut certificate_store, client_certificate, client_pkey) = CertificateStore::new_with_keypair(&config.pki_dir, application_description);
        if client_certificate.is_none() || client_pkey.is_none() {
            error!("Client is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.")
        }

        // Clients may choose to auto trust servers to save some messing around with rejected certs
        if config.trust_server_certs {
            certificate_store.trust_unknown_certs = true;
        }

        Client {
            config,
            sessions: Vec::new(),
            certificate_store: Arc::new(RwLock::new(certificate_store)),
        }
    }

    /// Returns a filled OPC UA [`ApplicationDescription`]
    /// struct using information from the config
    ///
    /// [`ApplicationDescription`]: ../../opcua_types/service_types/application_description/struct.ApplicationDescription.html
    ///
    pub fn application_description(&self) -> ApplicationDescription {
        self.config.application_description()
    }

    /// Connects to the named endpoint and creates / activates a [`Session`] for that endpoint.
    ///
    /// Returns with the session that has been established or an error.
    ///
    /// Important Note: sessions are protected objects that are shared from multiple threads both
    /// internally by the API and externally by your code. You should only lock your session
    /// for the smallest duration necessary and release it thereafter. i.e. scope protect your
    /// calls.
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn connect_and_activate(&mut self, endpoint_id: Option<&str>) -> Result<Arc<RwLock<Session>>, StatusCode> {
        // Ask the server associated with the default endpoint for its list of endpoints
        let endpoints = match self.get_server_endpoints() {
            Result::Err(status_code) => {
                error!("Can't get endpoints for server, error - {}", status_code);
                return Err(status_code);
            }
            Result::Ok(endpoints) => endpoints
        };

        info!("Server has these endpoints:");
        endpoints.iter().for_each(|e| println!("  {} - {:?} / {:?}", e.endpoint_url,
                                               SecurityPolicy::from_str(e.security_policy_uri.as_ref()).unwrap(),
                                               e.security_mode));

        // Create a session to an endpoint. If an endpoint id is specified use that
        let session = if let Some(endpoint_id) = endpoint_id {
            self.new_session_from_id(endpoint_id, &endpoints).unwrap()
        } else {
            self.new_session(&endpoints).unwrap()
        };

        {
            // Connect to the server
            let mut session = session.write().unwrap();
            if let Err(result) = session.connect_and_activate_session() {
                error!("Got an error while creating the default session - {}", result.description());
            }
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
            Err(format!("No default endpoint has been specified"))
        } else if let Some(endpoint) = self.config.endpoints.get(&default_endpoint_id) {
            Ok(endpoint.clone())
        } else {
            Err(format!("Cannot find default endpoint with id {}", default_endpoint_id))
        }
    }

    /// Creates a new [`Session`] using the default endpoint specified in the config. If
    /// there is no default, or the endpoint does not exist, this function will return an error
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn new_session(&mut self, endpoints: &[EndpointDescription]) -> Result<Arc<RwLock<Session>>, String> {
        let endpoint = self.default_endpoint()?;
        self.new_session_from_endpoint(&endpoint, endpoints)
    }

    /// Creates a new [`Session`] using the named endpoint id. If there is no
    /// endpoint of that id in the config, this function will return an error
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn new_session_from_id<T>(&mut self, endpoint_id: T, endpoints: &[EndpointDescription]) -> Result<Arc<RwLock<Session>>, String>
        where T: Into<String>
    {
        let endpoint_id = endpoint_id.into();
        let endpoint = {
            let endpoint = self.config.endpoints.get(&endpoint_id);
            if endpoint.is_none() {
                return Err(format!("Cannot find endpoint with id {}", endpoint_id));
            }
            endpoint.unwrap().clone()
        };
        self.new_session_from_endpoint(&endpoint, endpoints)
    }

    /// Creates a new [`Session`] using provided client endpoint and endpoint descriptions.
    /// If the endpoint does not exist or is in error, this function will return an error.
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    fn new_session_from_endpoint(&mut self, client_endpoint: &ClientEndpoint,
                                 endpoints: &[EndpointDescription]) -> Result<Arc<RwLock<Session>>, String>
    {
        let session_info = self.session_info_for_endpoint(client_endpoint, endpoints)?;
        self.new_session_from_info(session_info)
    }

    /// Creates an ad hoc new [`Session`] using the specified endpoint url,
    /// security policy and mode.
    ///
    /// [`Session`]: ../session/struct.Session.html
    ///
    pub fn new_session_from_info<T>(&mut self, session_info: T) -> Result<Arc<RwLock<Session>>, String> where T: Into<SessionInfo> {
        let session_info = session_info.into();
        if !is_opc_ua_binary_url(session_info.endpoint.endpoint_url.as_ref()) {
            Err(format!("Endpoint url {}, is not a valid / supported url", session_info.endpoint.endpoint_url))
        } else {
            let session = Arc::new(RwLock::new(Session::new(self.application_description(), self.certificate_store.clone(), session_info)));
            self.sessions.push(SessionEntry {
                session: session.clone(),
            });
            Ok(session)
        }
    }

    /// Fetches the client's public certificate and private key from the certificate store.
    fn get_client_cert_and_key(&self) -> (Option<X509>, Option<PrivateKey>) {
        let certificate_store = trace_read_lock_unwrap!(self.certificate_store);
        if let Ok((cert, key)) = certificate_store.read_own_cert_and_pkey() {
            (Some(cert), Some(key))
        } else {
            (None, None)
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
                error!("Cannot create a server url from the specified endpoint url {}", default_endpoint.url);
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            error!("There is no default endpoint, so cannot get endpoints");
            Err(StatusCode::BadUnexpectedError)
        }
    }

    /// Connects to the specified server_url with a None/None connection and asks for a list of
    /// [`EndpointDescription`] that it hosts. If there is an error, the function will
    /// return an error.
    ///
    /// [`EndpointDescription`]: ../../opcua_types/service_types/endpoint_description/struct.EndpointDescription.html
    ///
    pub fn get_server_endpoints_from_url<T>(&self, server_url: T) -> Result<Vec<EndpointDescription>, StatusCode>
        where T: Into<String>
    {
        let server_url = server_url.into();
        let preferred_locales = Vec::new();
        let (client_certificate, client_pkey) = self.get_client_cert_and_key();

        // Most of these fields mean nothing when getting endpoints
        let endpoint = Self::make_endpoint_description(&server_url);
        let session_info = SessionInfo {
            endpoint,
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales,
            client_pkey,
            client_certificate,
        };
        let mut session = Session::new(self.application_description(), self.certificate_store.clone(), session_info);
        let _ = session.connect()?;
        let result = session.get_endpoints()?;
        let _ = session.disconnect();
        Ok(result)
    }

    /// Connects to a discovery server and asks the server for a list of
    /// available server [`ApplicationDescription`].
    ///
    /// [`ApplicationDescription`]: ../../opcua_types/service_types/application_description/struct.ApplicationDescription.html
    ///
    pub fn find_servers<T>(&mut self, discovery_endpoint_url: T) -> Result<Vec<ApplicationDescription>, StatusCode>
        where T: Into<String>
    {
        let discovery_endpoint_url = discovery_endpoint_url.into();
        debug!("find_servers, {}", discovery_endpoint_url);
        let endpoint = Self::make_endpoint_description(&discovery_endpoint_url);
        let session = self.new_session_from_info(endpoint);
        if let Ok(session) = session {
            let mut session = trace_write_lock_unwrap!(session);
            // Connect & activate the session.
            let connected = session.connect();
            if let Ok(_) = connected {
                // Find me some some servers
                let servers = session.find_servers(discovery_endpoint_url.clone());
                let result = if let Ok(servers) = servers {
                    Ok(servers)
                } else {
                    let result = servers.unwrap_err();
                    error!("Cannot find servers on discovery server {} - check this error - {:?}", discovery_endpoint_url, result);
                    Err(result)
                };
                let _ = session.disconnect();
                result
            } else {
                let result = connected.unwrap_err();
                error!("Cannot connect to {} - check this error - {:?}", discovery_endpoint_url, result);
                Err(result)
            }
        } else {
            let result = StatusCode::BadUnexpectedError;
            error!("Cannot create a sesion to {} - check if url is malformed", discovery_endpoint_url);
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
    /// whatever is required to make the discovery server trust the registering server. For example
    /// the standard OPC foundation discovery server will drop the server's cert in a rejected/
    /// folder and this cert has to be moved to a trusted/certs/ folder.
    pub fn register_server<T>(&mut self, discovery_endpoint_url: T,
                              server: RegisteredServer) -> Result<(), StatusCode>
        where T: Into<String> {
        let discovery_endpoint_url = discovery_endpoint_url.into();
        // Get a list of endpoints from the discovery server
        debug!("register_server({}, {:?}", discovery_endpoint_url, server);
        let endpoints = self.get_server_endpoints_from_url(discovery_endpoint_url.clone())?;
        if endpoints.is_empty() {
            Err(StatusCode::BadUnexpectedError)
        } else {
            // Now choose the strongest endpoint to register through
            if let Some(endpoint) = endpoints.iter()
                .filter(|e| self.is_supported_endpoint(*e))
                .max_by(|a, b| a.security_level.cmp(&b.security_level)) {
                debug!("Registering this server via discovery endpoint {:?}", endpoint);
                let session = self.new_session_from_info(endpoint.clone());
                if let Ok(session) = session {
                    let mut session = trace_write_lock_unwrap!(session);
                    let connected = session.connect();
                    if let Ok(_) = connected {
                        // Register with the server
                        let result = session.register_server(server);
                        let _ = session.disconnect();
                        result
                    } else {
                        let result = connected.unwrap_err();
                        error!("Cannot connect to {} - check this error - {:?}", discovery_endpoint_url, result);
                        Err(result)
                    }
                } else {
                    error!("Cannot create a sesion to {} - check if url is malformed", discovery_endpoint_url);
                    Err(StatusCode::BadUnexpectedError)
                }
            } else {
                error!("Can't find an endpoint that we call register server on");
                Err(StatusCode::BadUnexpectedError)
            }
        }
    }

    /// Makes an endpoint description from a url, assuming the endpoint to have no encryption
    fn make_endpoint_description(server_url: &str) -> EndpointDescription {
        EndpointDescription {
            endpoint_url: UAString::from(server_url),
            security_policy_uri: UAString::from(SecurityPolicy::None.to_uri()),
            security_mode: MessageSecurityMode::None,
            server: ApplicationDescription::null(),
            security_level: 0,
            server_certificate: ByteString::null(),
            transport_profile_uri: UAString::null(),
            user_identity_tokens: None,
        }
    }

    /// Finds a matching endpoint, one that most closely matches the host, path, security policy
    /// and security mode used as inputs. The function will fallback to omit the host in its
    /// comparison if no exact match is found.
    pub fn find_server_endpoint<T>(&self, endpoints: &[EndpointDescription], endpoint_url: T,
                                   security_policy: SecurityPolicy,
                                   security_mode: MessageSecurityMode) -> Option<EndpointDescription>
        where T: Into<String> {
        // Iterate the supplied endpoints looking for the closest match.
        let security_policy_uri = security_policy.to_uri();
        let endpoint_url = endpoint_url.into();

        // Do an exact match first
        let result = endpoints.iter().find(|e| {
            e.security_mode == security_mode &&
                e.security_policy_uri.as_ref() == security_policy_uri &&
                url_matches(e.endpoint_url.as_ref(), &endpoint_url)
        }).map(|e| e.clone());

        // If something was found, return it, otherwise try a fuzzier match, that ignores the hostname.
        if result.is_some() {
            result
        } else {
            endpoints.iter().find(|e| {
                e.security_mode == security_mode &&
                    e.security_policy_uri.as_ref() == security_policy_uri &&
                    url_matches_except_host(e.endpoint_url.as_ref(), &endpoint_url)
            }).map(|e| e.clone())
        }
    }

    /// Determine if we recognize the security of this endpoint
    fn is_supported_endpoint(&self, endpoint: &EndpointDescription) -> bool {
        if let Ok(security_policy) = SecurityPolicy::from_str(endpoint.security_policy_uri.as_ref()) {
            match security_policy {
                SecurityPolicy::Unknown => false,
                _ => true
            }
        } else {
            false
        }
    }

    /// Returns an identity token corresponding to the matching user in the configuration. Or None
    /// if there is no matching token.
    fn client_identity_token<T>(&self, user_token_id: T) -> Option<IdentityToken> where T: Into<String> {
        let user_token_id = user_token_id.into();
        if user_token_id == ANONYMOUS_USER_TOKEN_ID {
            Some(IdentityToken::Anonymous)
        } else if let Some(token) = self.config.user_tokens.get(&user_token_id) {
            Some(IdentityToken::UserName(token.user.clone(), token.password.clone()))
        } else {
            None
        }
    }

    /// Find an endpoint supplied from the list of endpoints that matches the input criteria
    pub fn find_matching_endpoint<T>(endpoints: &[EndpointDescription],
                                     endpoint_url: T, security_policy: SecurityPolicy,
                                     security_mode: MessageSecurityMode) -> Option<EndpointDescription>
        where T: Into<String>
    {
        let endpoint_url = endpoint_url.into();
        if security_policy == SecurityPolicy::Unknown {
            panic!("Can't match against unknown security policy");
        }
        endpoints.iter().find(|e| {
            // Endpoint matches if the security mode, policy and url match
            security_mode == e.security_mode &&
                security_policy == SecurityPolicy::from_uri(e.security_policy_uri.as_ref()) &&
                url_matches_except_host(&endpoint_url, e.endpoint_url.as_ref())
        }).map(|e| e.clone())
    }

    /// Creates a [`SessionInfo`](SessionInfo) information from the supplied client endpoint.
    fn session_info_for_endpoint(&self, client_endpoint: &ClientEndpoint, endpoints: &[EndpointDescription]) -> Result<SessionInfo, String> {
        // Enumerate endpoints looking for matching one
        if let Ok(security_policy) = SecurityPolicy::from_str(&client_endpoint.security_policy) {
            let security_mode = MessageSecurityMode::from(client_endpoint.security_mode.as_ref());
            if security_mode != MessageSecurityMode::Invalid {
                let endpoint_url = client_endpoint.url.clone();
                // Now find a matching endpoint from those on the server
                let endpoint = Self::find_matching_endpoint(endpoints, endpoint_url.clone(), security_policy, security_mode);
                if endpoint.is_none() {
                    Err(format!("Endpoint {}, {:?} / {:?} does not match against any supplied by the server", endpoint_url, security_policy, security_mode))
                } else if let Some(user_identity_token) = self.client_identity_token(client_endpoint.user_token_id.clone()) {
                    info!("Creating a session for endpoint {}, {:?} / {:?}", endpoint_url, security_policy, security_mode);
                    let preferred_locales = self.config.preferred_locales.clone();
                    let (client_certificate, client_pkey) = self.get_client_cert_and_key();
                    Ok(SessionInfo {
                        endpoint: endpoint.unwrap().clone(),
                        user_identity_token,
                        preferred_locales,
                        client_pkey,
                        client_certificate,
                    })
                } else {
                    Err(format!("Endpoint {} user id cannot be found", client_endpoint.user_token_id))
                }
            } else {
                Err(format!("Endpoint {} security mode {} is invalid", client_endpoint.url, client_endpoint.security_mode))
            }
        } else {
            Err(format!("Endpoint {} security policy {} is invalid", client_endpoint.url, client_endpoint.security_policy))
        }
    }
}