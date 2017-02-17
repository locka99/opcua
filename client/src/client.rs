use std::sync::{Arc, Mutex};

use opcua_core::types::*;
use opcua_core::services::*;

use session::*;

pub struct Client {
    /// The application description supplied by the client to all sessions created by the client
    pub client_description: ApplicationDescription,
    /// A list of sessions made by the client. They are protect since they will be running on their
    /// own independent threads.
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
    pub fn new_session(&mut self, endpoint_url: &str) -> Arc<Mutex<Session>> {
        let session = Arc::new(Mutex::new(Session::new(endpoint_url)));
        self.sessions.push(session.clone());
        session
    }
}