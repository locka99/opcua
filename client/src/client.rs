use std::sync::{Arc, Mutex};
use std::str::FromStr;

use opcua_types::{UAString, LocalizedText, MessageSecurityMode, ApplicationDescription, ApplicationType, EndpointDescription, StatusCode};
use opcua_types::{is_opc_ua_binary_url, server_url_from_endpoint_url, url_matches, url_matches_except_host};
use opcua_types::StatusCode::BAD_UNEXPECTED_ERROR;
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
    /// Client certificate
    client_certificate: Option<X509>,
    /// Client private key
    client_pkey: Option<PKey>,
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
            client_certificate,
            client_pkey,
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
    pub fn new_session_default_endpoint(&mut self) -> Result<Arc<Mutex<Session>>, String> {
        let endpoint = self.default_endpoint()?;
        self.new_session_from_endpoint(&endpoint)
    }

    /// Creates a new `Session` using the endpoint id specified in the config. If there is no
    /// endpoint of that id, this function will return an error
    pub fn new_session_endpoint_id(&mut self, endpoint_id: &str) -> Result<Arc<Mutex<Session>>, String> {
        let endpoint = {
            let endpoint = self.config.endpoints.get(endpoint_id);
            if endpoint.is_none() {
                return Err(format!("Cannot find endpoint with id {}", endpoint_id));
            }
            endpoint.unwrap().clone()
        };
        self.new_session_from_endpoint(&endpoint)
    }

    /// Makes a None/None connection to the server in the default endpoint to obtain a list of
    /// endpoints
    pub fn get_server_endpoints_default(&self) -> Result<Vec<EndpointDescription>, StatusCode> {
        if let Ok(default_endpoint) = self.default_endpoint() {
            if let Ok(server_url) = server_url_from_endpoint_url(&default_endpoint.url) {
                self.get_server_endpoints(&server_url)
            } else {
                error!("Cannot create a server url from the specified endpoint url {}", default_endpoint.url);
                Err(BAD_UNEXPECTED_ERROR)
            }
        } else {
            error!("There is no default endpoint, so cannot get endpoints");
            Err(BAD_UNEXPECTED_ERROR)
        }
    }

    /// Makes a None/None connection to the server to obtain a list of endpoints
    pub fn get_server_endpoints(&self, server_url: &str) -> Result<Vec<EndpointDescription>, StatusCode> {
        let preferred_locales = Vec::new();
        let session_info = SessionInfo {
            url: server_url.to_string(),
            security_policy: SecurityPolicy::None,
            security_mode: MessageSecurityMode::None,
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales
        };
        let mut session = Session::new(self.application_description(), self.certificate_store.clone(), session_info);
        let _ = session.connect()?;
        session.get_endpoints()
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

    /// Creates a new `Session` using the endpoint id referring to an endpoint in the client
    /// configuration. If the named endpoint does not exist oris in error, this function will return an error.
    pub fn new_session_from_endpoint(&mut self, endpoint: &ClientEndpoint) -> Result<Arc<Mutex<Session>>, String> {
        let session_info = self.session_info_for_endpoint(endpoint)?;
        self.new_session(session_info)
    }

    /// Creates an ad hoc new anonymous `Session` using the specified endpoint url, security policy and mode.
    pub fn new_session(&mut self, session_info: SessionInfo) -> Result<Arc<Mutex<Session>>, String> {
        if !is_opc_ua_binary_url(&session_info.url) {
            Err(format!("Endpoint url {}, is not a valid / supported url", session_info.url))
        } else {
            let session = Arc::new(Mutex::new(Session::new(self.application_description(), self.certificate_store.clone(), session_info)));
            self.sessions.push(session.clone());
            Ok(session)
        }
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

    fn session_info_for_endpoint(&self, endpoint: &ClientEndpoint) -> Result<SessionInfo, String> {
        // Enumerate endpoints looking for matching one
        if let Ok(security_policy) = SecurityPolicy::from_str(&endpoint.security_policy) {
            let security_mode = MessageSecurityMode::from(endpoint.security_mode.as_ref());
            if security_mode != MessageSecurityMode::Invalid {
                let url = endpoint.url.clone();
                if let Some(user_identity_token) = self.client_identity_token(&endpoint.user_token_id) {
                    let preferred_locales = self.config.preferred_locales.clone();
                    Ok(SessionInfo {
                        url,
                        security_policy,
                        security_mode,
                        user_identity_token,
                        preferred_locales
                    })
                } else {
                    Err(format!("Endpoint {} user id cannot be found", endpoint.user_token_id))
                }
            } else {
                Err(format!("Endpoint {} security mode {} is invalid", endpoint.url, endpoint.security_mode))
            }
        } else {
            Err(format!("Endpoint {} security policy {} is invalid", endpoint.url, endpoint.security_policy))
        }
    }
}