use std::sync::{Arc, Mutex};

use opcua_core::prelude::*;

use config::ClientConfig;
use session::Session;

/// The client-side OPC UA state. A client can have a description, multiple open sessions
/// and a certificate store.
pub struct Client {
    /// The application description supplied by the client to all sessions created by the client
    pub client_description: ApplicationDescription,
    /// A list of sessions made by the client. They are protected since a session may or may not be
    /// running on an independent thread.
    pub sessions: Vec<Arc<Mutex<Session>>>,
    /// Certificate store is where certificates go.
    pub certificate_store: Arc<Mutex<CertificateStore>>
}

impl Client {
    /// Creates a new `Client` instance. The application name and uri are supplied as arguments to
    /// this call and are passed to each session that connects hereafter.
    pub fn new(config: ClientConfig) -> Client {
        Client {
            client_description: ApplicationDescription {
                application_uri: UAString::from(config.application_uri.as_ref()),
                application_name: LocalizedText::new("", &config.application_name),
                application_type: ApplicationType::Client,
                product_uri: UAString::null(),
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
            },
            sessions: Vec::new(),
            certificate_store: Arc::new(Mutex::new(CertificateStore::new(&config.pki_dir)))
        }
    }

    /// Creates a new session from this client.
    pub fn new_session(&mut self, endpoint_url: &str, security_policy: SecurityPolicy) -> Result<Arc<Mutex<Session>>, String> {
        if !is_opc_ua_binary_url(endpoint_url) {
            Err(format!("Endpoint url {}, is not a valid / supported url", endpoint_url))
        } else {
            let session = Arc::new(Mutex::new(Session::new(self.certificate_store.clone(), endpoint_url, security_policy)));
            self.sessions.push(session.clone());
            Ok(session)
        }
    }
}