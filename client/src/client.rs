use std::sync::{Arc, Mutex};
use std::str::FromStr;

use opcua_core::prelude::*;

use config::ClientConfig;
use session::Session;

/// The client-side OPC UA state. A client can have a description, multiple open sessions
/// and a certificate store.
pub struct Client {
    /// Client configuration
    config: ClientConfig,
    /// A list of sessions made by the client. They are protected since a session may or may not be
    /// running on an independent thread.
    sessions: Vec<Arc<Mutex<Session>>>,
    /// Certificate store is where certificates go.
    certificate_store: Arc<Mutex<CertificateStore>>
}

impl Client {
    /// Creates a new `Client` instance. The application name and uri are supplied as arguments to
    /// this call and are passed to each session that connects hereafter.
    pub fn new(config: ClientConfig) -> Client {
        let pki_dir = config.pki_dir.clone();
        Client {
            config,
            sessions: Vec::new(),
            certificate_store: Arc::new(Mutex::new(CertificateStore::new(&pki_dir)))
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

    /// Creates a new `Session` using the default endpoint specified by name in the config. If there is no
    /// default, or the name does not exist, this function will return an error
    pub fn new_session_default(&mut self) -> Result<Arc<Mutex<Session>>, String> {
        let default_endpoint = self.config.default_endpoint.clone();
        if default_endpoint.is_empty() {
            Err(format!("No default endpoint has been specified"))
        } else {
            self.new_session_from_endpoint(&default_endpoint)
        }
    }

    /// Creates a new `Session` using the endpoint id. If the named endpoint does not exist or
    /// is in error, this function will return an error.
    pub fn new_session_from_endpoint(&mut self, id: &str) -> Result<Arc<Mutex<Session>>, String> {
        // Enumerate endpoints looking for matching one
        let (url, security_policy, security_mode) = {
            let endpoint = self.config.endpoints.iter().find(|e| &e.id == id);
            if let Some(ref endpoint) = endpoint {
                if let Ok(security_policy) = SecurityPolicy::from_str(&endpoint.security_policy) {
                    let security_mode = MessageSecurityMode::from(endpoint.security_mode.as_ref());
                    if security_mode != MessageSecurityMode::Invalid {
                        let url = endpoint.url.clone();
                        (url, security_policy, security_mode)
                    } else {
                        return Err(format!("Endpoint {} security mode {} is invalid", id, endpoint.security_mode));
                    }
                } else {
                    return Err(format!("Endpoint {} security policy {} is invalid", id, endpoint.security_policy));
                }
            } else {
                return Err(format!("Endpoint {} cannot be found in list of configured endpoints. Check config file", id));
            }
        };
        self.new_session(&url, security_policy, security_mode)
    }

    /// Creates a new `Session` using the specified endpoint url, security policy and mode.
    pub fn new_session(&mut self, endpoint_url: &str, security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> Result<Arc<Mutex<Session>>, String> {
        if !is_opc_ua_binary_url(endpoint_url) {
            Err(format!("Endpoint url {}, is not a valid / supported url", endpoint_url))
        } else {
            let session = Arc::new(Mutex::new(Session::new(self.certificate_store.clone(), endpoint_url, security_policy, security_mode)));
            self.sessions.push(session.clone());
            Ok(session)
        }
    }
}