use opcua_types::*;

use DateTimeUTC;
use subscriptions::PublishResponseEntry;
use subscriptions::subscriptions::Subscriptions;
use server::ServerState;

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

/// Structure that captures diagnostics information for the session
#[derive(Clone)]
pub struct SessionDiagnostics {}

impl SessionDiagnostics {
    pub fn new() -> SessionDiagnostics {
        SessionDiagnostics {}
    }
}

const MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE: usize = 100;
const PUBLISH_REQUEST_TIMEOUT: i64 = 30000;

/// Session state is anything associated with the session at the message / service level
pub struct Session {
    /// Subscriptions associated with the session
    pub subscriptions: Subscriptions,
    /// The session identifier
    pub session_id: NodeId,
    /// Indicates if the session has received an ActivateSession
    pub activated: bool,
    /// Flag to indicate session should be terminated
    pub terminate_session: bool,
    /// Security policy
    pub security_policy_uri: String,
    /// Client's certificate
    pub client_certificate: ByteString,
    /// Authentication token for the session
    pub authentication_token: NodeId,
    /// Session nonce
    pub session_nonce: ByteString,
    /// Session timeout
    pub session_timeout: Double,
    /// User identity token
    pub user_identity: Option<ExtensionObject>,
    /// Negotiated max request message size
    pub max_request_message_size: UInt32,
    /// Negotiated max response message size
    pub max_response_message_size: UInt32,
    /// Endpoint url for this session
    pub endpoint_url: UAString,
    /// Diagnostics associated with the session
    pub diagnostics: SessionDiagnostics,
    /// Internal value used to create new session ids.
    last_session_id: UInt32,
}

impl Session {
    pub fn new() -> Session {
        let max_publish_requests = MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE;
        Session {
            subscriptions: Subscriptions::new(max_publish_requests, PUBLISH_REQUEST_TIMEOUT),
            session_id: NodeId::null(),
            activated: false,
            terminate_session: false,
            client_certificate: ByteString::null(),
            security_policy_uri: String::new(),
            authentication_token: NodeId::null(),
            session_nonce: ByteString::null(),
            session_timeout: 0f64,
            user_identity: None,
            max_request_message_size: 0,
            max_response_message_size: 0,
            endpoint_url: UAString::null(),
            diagnostics: SessionDiagnostics::new(),
            last_session_id: 0,
        }
    }

    pub fn next_session_id(&mut self) -> NodeId {
        self.last_session_id += 1;
        NodeId::new_numeric(1, self.last_session_id as u64)
    }

    pub fn enqueue_publish_request(&mut self, server_state: &ServerState, request_id: UInt32, request: PublishRequest) -> Result<(), SupportedMessage> {
        let address_space = server_state.address_space.lock().unwrap();
        self.subscriptions.enqueue_publish_request(&address_space, request_id, request)
    }

    pub fn tick_subscriptions(&mut self, server_state: &ServerState, receive_publish_request: bool) -> Result<(), StatusCode> {
        let address_space = server_state.address_space.lock().unwrap();
        self.subscriptions.tick(receive_publish_request, &address_space)
    }

    /// Iterates through the existing queued publish requests and creates a timeout
    /// publish response any that have expired.
    pub fn expire_stale_publish_requests(&mut self, now: &DateTimeUTC) {
        self.subscriptions.expire_stale_publish_requests(now);
    }
}
