use std::sync::{Arc, Mutex};
use std::str::FromStr;

use opcua_types::{UAString, ByteString, LocalizedText, MessageSecurityMode};
use opcua_types::{is_opc_ua_binary_url, server_url_from_endpoint_url, url_matches, url_matches_except_host};
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::BadUnexpectedError;
use opcua_types::service_types::{ApplicationDescription, ApplicationType, EndpointDescription};
use opcua_core::crypto::{SecurityPolicy, CertificateStore, X509, PKey};

use config::{ClientConfig, ClientEndpoint, ANONYMOUS_USER_TOKEN_ID};
use session::{Session, SessionInfo};

pub enum IdentityToken {
    Anonymous,
    UserName(String, String),
}

/// The client-side OPC UA state. A client can have a description, multiple open sessions
/// and a certificate store.
pub struct Client {
    /// Client configuration
    config: ClientConfig,
    /// A list of sessions made by the client. They are protected since a session may or may not be
    /// running on an independent thread.
    sessions: Vec<Arc<Mutex<Session>>>,
    /// Certificate store is where certificates go.
    certificate_store: Arc<Mutex<CertificateStore>>,
}

impl Client {
    /// Creates a new `Client` instance. The application name and uri are supplied as arguments to
    /// this call and are passed to each session that connects hereafter.
    pub fn new(config: ClientConfig) -> Client {
        let (certificate_store, client_certificate, client_pkey) = CertificateStore::new_with_keypair(&config.pki_dir, config.create_sample_keypair);
        if client_certificate.is_none() || client_pkey.is_none() {
            error!("Client is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.")
        }
        Client {
            config,
            sessions: Vec::new(),
            certificate_store: Arc::new(Mutex::new(certificate_store)),
        }
    }

    /// Returns a filled OPCUA `ApplicationDescription` struct using information from the config
    pub fn application_description(&self) -> ApplicationDescription {
        ApplicationDescription {
            application_uri: UAString::from(self.config.application_uri.as_ref()),
            application_name: LocalizedText::new("", &self.config.application_name),
            application_type: ApplicationType::Client,
            product_uri: UAString::from(self.config.product_uri.as_ref()),
            gateway_server_uri: UAString::null(),
            discovery_profile_uri: UAString::null(),
            discovery_urls: None,
        }
    }

    /// Gets the default endpoint id
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

    /// Creates a new `Session` using the default endpoint specified in the config. If there is no
    /// default, or the endpoint does not exist, this function will return an error
    pub fn new_session(&mut self, endpoints: &[EndpointDescription]) -> Result<Arc<Mutex<Session>>, String> {
        let endpoint = self.default_endpoint()?;
        self.new_session_from_endpoint(&endpoint, endpoints)
    }

    /// Creates a new `Session` using the endpoint id specified in the config. If there is no
    /// endpoint of that id, this function will return an error
    pub fn new_session_from_id(&mut self, endpoint_id: &str, endpoints: &[EndpointDescription]) -> Result<Arc<Mutex<Session>>, String> {
        let endpoint = {
            let endpoint = self.config.endpoints.get(endpoint_id);
            if endpoint.is_none() {
                return Err(format!("Cannot find endpoint with id {}", endpoint_id));
            }
            endpoint.unwrap().clone()
        };
        self.new_session_from_endpoint(&endpoint, endpoints)
    }

    /// Creates a new `Session` using the endpoint id referring to an endpoint in the client
    /// configuration. If the named endpoint does not exist oris in error, this function will return an error.
    pub fn new_session_from_endpoint(&mut self, client_endpoint: &ClientEndpoint, endpoints: &[EndpointDescription]) -> Result<Arc<Mutex<Session>>, String> {
        let session_info = self.session_info_for_endpoint(client_endpoint, endpoints)?;
        self.new_session_from_info(session_info)
    }

    /// Creates an ad hoc new `Session` using the specified endpoint url, security policy and mode.
    pub fn new_session_from_info<T>(&mut self, session_info: T) -> Result<Arc<Mutex<Session>>, String> where T: Into<SessionInfo> {
        let session_info = session_info.into();
        if !is_opc_ua_binary_url(session_info.endpoint.endpoint_url.as_ref()) {
            Err(format!("Endpoint url {}, is not a valid / supported url", session_info.endpoint.endpoint_url))
        } else {
            let session = Arc::new(Mutex::new(Session::new(self.application_description(), self.certificate_store.clone(), session_info)));
            self.sessions.push(session.clone());
            Ok(session)
        }
    }

    fn get_client_cert_and_key(&self) -> (Option<X509>, Option<PKey>) {
        let certificate_store = self.certificate_store.lock().unwrap();
        if let Ok((cert, key)) = certificate_store.read_own_cert_and_pkey() {
            (Some(cert), Some(key))
        } else {
            (None, None)
        }
    }

    /// Makes a None/None connection to the server in the default endpoint to obtain a list of
    /// endpoints
    pub fn get_server_endpoints(&self) -> Result<Vec<EndpointDescription>, StatusCode> {
        if let Ok(default_endpoint) = self.default_endpoint() {
            if let Ok(server_url) = server_url_from_endpoint_url(&default_endpoint.url) {
                self.get_server_endpoints_from_url(&server_url)
            } else {
                error!("Cannot create a server url from the specified endpoint url {}", default_endpoint.url);
                Err(BadUnexpectedError)
            }
        } else {
            error!("There is no default endpoint, so cannot get endpoints");
            Err(BadUnexpectedError)
        }
    }

    /// Makes a None/None connection to the server to obtain a list of endpoints
    pub fn get_server_endpoints_from_url(&self, server_url: &str) -> Result<Vec<EndpointDescription>, StatusCode> {
        let preferred_locales = Vec::new();
        let (client_certificate, client_pkey) = self.get_client_cert_and_key();

        // Most of these fields mean nothing when getting endpoints
        let endpoint = Self::make_endpoint_description(server_url);
        let session_info = SessionInfo {
            endpoint,
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales,
            client_pkey,
            client_certificate,
        };
        let mut session = Session::new(self.application_description(), self.certificate_store.clone(), session_info);
        let _ = session.connect()?;
        session.get_endpoints()
    }

    /// Creates a temporary `Session` to the specified discovery endpoint and returns the server results that it finds
    pub fn find_servers<T>(&mut self, discovery_endpoint_url: T) -> Result<Vec<ApplicationDescription>, StatusCode> where T: Into<String> {
        let discovery_endpoint_url = discovery_endpoint_url.into();
        debug!("Creating a temporary session to discovery server {}", discovery_endpoint_url);
        let endpoint = Self::make_endpoint_description(&discovery_endpoint_url);
        let session = self.new_session_from_info(endpoint);
        if let Ok(session) = session {
            let mut session = session.lock().unwrap();
            // Connect & activate the session.
            let connected = session.connect();
            if let Ok(_) = connected {
                // Find me some some servers
                let servers = session.find_servers(discovery_endpoint_url.clone());
                if let Ok(servers) = servers {
                    Ok(servers)
                } else {
                    let result = servers.unwrap_err();
                    error!("Cannot find servers on discovery server {} - check this error - {:?}", discovery_endpoint_url, result);
                    Err(result)
                }
            } else {
                let result = connected.unwrap_err();
                error!("Cannot connect to {} - check this error - {:?}", discovery_endpoint_url, result);
                Err(result)
            }
        } else {
            let result = BadUnexpectedError;
            error!("Cannot create a sesion to {} - check if url is malformed", discovery_endpoint_url);
            Err(result)
        }
    }

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
    pub fn find_server_endpoint(&self, endpoints: &[EndpointDescription], endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> Option<EndpointDescription> {
        // Iterate the supplied endpoints looking for the closest match.
        let security_policy_uri = security_policy.to_uri();
        // Do an exact match first
        for e in endpoints {
            if e.security_policy_uri.as_ref() == security_policy_uri &&
                e.security_mode == security_mode &&
                url_matches(e.endpoint_url.as_ref(), endpoint_url) {
                return Some(e.clone());
            }
        }
        // Now try a fuzzier match, ignoring the hostname part
        for e in endpoints {
            if e.security_policy_uri.as_ref() == security_policy_uri &&
                e.security_mode == security_mode &&
                url_matches_except_host(e.endpoint_url.as_ref(), endpoint_url) {
                return Some(e.clone());
            }
        }
        None
    }


    fn client_identity_token(&self, user_token_id: &str) -> Option<IdentityToken> {
        if user_token_id == ANONYMOUS_USER_TOKEN_ID {
            Some(IdentityToken::Anonymous)
        } else {
            if let Some(token) = self.config.user_tokens.get(user_token_id) {
                Some(IdentityToken::UserName(token.user.clone(), token.password.clone()))
            } else {
                None
            }
        }
    }

    /// Find an endpoint supplied from the list of endpoints that matches the input criteria
    pub fn find_matching_endpoint(endpoints: &[EndpointDescription], endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> Option<EndpointDescription> {
        if security_policy == SecurityPolicy::Unknown {
            panic!("Can't match against unknown security policy");
        }
        for e in endpoints.iter() {
            if security_policy == SecurityPolicy::from_uri(e.security_policy_uri.as_ref()) &&
                security_mode == e.security_mode &&
                url_matches_except_host(endpoint_url, e.endpoint_url.as_ref()) {
                return Some(e.clone());
            }
        }
        None
    }

    fn session_info_for_endpoint(&self, client_endpoint: &ClientEndpoint, endpoints: &[EndpointDescription]) -> Result<SessionInfo, String> {
        // Enumerate endpoints looking for matching one
        if let Ok(security_policy) = SecurityPolicy::from_str(&client_endpoint.security_policy) {
            let security_mode = MessageSecurityMode::from(client_endpoint.security_mode.as_ref());
            if security_mode != MessageSecurityMode::Invalid {
                let endpoint_url = client_endpoint.url.clone();
                // Now find a matching endpoint from those on the server
                let endpoint = Self::find_matching_endpoint(endpoints, &endpoint_url, security_policy, security_mode);
                if endpoint.is_none() {
                    Err(format!("Endpoint {}, {:?} / {:?} does not match against any supplied by the server", endpoint_url, security_policy, security_mode))
                } else if let Some(user_identity_token) = self.client_identity_token(&client_endpoint.user_token_id) {
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