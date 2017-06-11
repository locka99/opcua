use std::sync::{Arc, Mutex};

use opcua_core::types::*;
use opcua_core::services::*;

use session::*;

pub struct Client {
    /// The application description supplied by the client to all sessions created by the client
    pub client_description: ApplicationDescription,
    /// A list of sessions made by the client. They are protected since a session may be running on
    /// an independent thread.
    pub sessions: Vec<Arc<Mutex<Session>>>,
}

impl Client {
    /// Creates a new `Client` instance. The application name and uri are supplied as arguments to
    /// this call and are passed to each session that connects hereafter
    pub fn new(application_name: &str, application_uri: &str) -> Client {
        Client {
            client_description: ApplicationDescription {
                application_uri: UAString::from_str(application_uri),
                application_name: LocalizedText::new("", application_name),
                application_type: ApplicationType::Client,
                product_uri: UAString::null(),
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: None,
            },
            sessions: Vec::new()
        }
    }

    /// Creates a new session from this client.
    pub fn new_session(&mut self, endpoint_url: &str) -> Result<Arc<Mutex<Session>>, String> {
        if !is_opc_ua_binary_url(endpoint_url) {
            Err(format!("Endpoint url {}, is not a valid / supported url", endpoint_url));
        } else {
            let session = Arc::new(Mutex::new(Session::new(endpoint_url)));
            self.sessions.push(session.clone());
            Ok(session)
        }
    }
}