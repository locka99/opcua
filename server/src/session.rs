// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock
use std::{
    collections::{HashSet, VecDeque},
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, RwLock,
    },
};

use chrono::Utc;

use opcua_core::comms::secure_channel::{Role, SecureChannel};
use opcua_crypto::X509;
use opcua_types::{service_types::PublishRequest, status_code::StatusCode, *};

use crate::{
    address_space::{AddressSpace, UserAccessLevel},
    continuation_point::BrowseContinuationPoint,
    diagnostics::ServerDiagnostics,
    identity_token::IdentityToken,
    server::Server,
    session_diagnostics::SessionDiagnostics,
    subscriptions::subscription::TickReason,
    subscriptions::subscriptions::Subscriptions,
};

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

const PUBLISH_REQUEST_TIMEOUT: i64 = 30000;

lazy_static! {
    static ref NEXT_SESSION_ID: AtomicI32 = AtomicI32::new(1);
}

fn next_session_id() -> NodeId {
    // Session id will be a string identifier
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    let session_id = format!("Session-{}", session_id);
    NodeId::new(1, session_id)
}

pub enum ServerUserIdentityToken {
    Empty,
    AnonymousIdentityToken,
    UserNameIdentityToken(UserIdentityToken),
    X509IdentityToken(X509IdentityToken),
    Invalid(ExtensionObject),
}

/// The Session is any state maintained between the client and server
pub struct Session {
    /// Subscriptions associated with the session
    subscriptions: Subscriptions,
    /// The session identifier
    session_id: NodeId,
    /// Security policy
    security_policy_uri: String,
    /// Client's certificate
    client_certificate: Option<X509>,
    /// Authentication token for the session
    authentication_token: NodeId,
    /// Secure channel state
    secure_channel: Arc<RwLock<SecureChannel>>,
    /// Session nonce
    session_nonce: ByteString,
    /// Session name (supplied by client)
    session_name: UAString,
    /// Session timeout
    session_timeout: f64,
    /// User identity token
    user_identity: IdentityToken,
    /// Session's preferred locale ids
    locale_ids: Option<Vec<UAString>>,
    /// Negotiated max request message size
    max_request_message_size: u32,
    /// Negotiated max response message size
    max_response_message_size: u32,
    /// Endpoint url for this session
    endpoint_url: UAString,
    /// Maximum number of continuation points
    max_browse_continuation_points: usize,
    /// Browse continuation points (oldest to newest)
    browse_continuation_points: VecDeque<BrowseContinuationPoint>,
    /// Diagnostics associated with the server
    diagnostics: Arc<RwLock<ServerDiagnostics>>,
    /// Diagnostics associated with the session
    session_diagnostics: Arc<RwLock<SessionDiagnostics>>,
    /// Indicates if the session has received an ActivateSession
    activated: bool,
    /// Flag to indicate session should be terminated
    terminate_session: bool,
    /// Time that session was terminated, helps with recovering sessions, or clearing them out
    terminated_at: DateTimeUtc,
    /// Flag indicating session is actually terminated
    terminated: bool,
    /// Flag indicating broadly if this session may modify the address space by adding or removing
    /// nodes or references to nodes.
    can_modify_address_space: bool,
    /// Timestamp of the last service request to have happened (only counts service requests while there is a session)
    last_service_request_timestamp: DateTimeUtc,
}

impl Drop for Session {
    fn drop(&mut self) {
        info!("Session is being dropped");
        let mut diagnostics = trace_write_lock_unwrap!(self.diagnostics);
        diagnostics.on_destroy_session(self);
    }
}

impl Session {
    #[cfg(test)]
    pub fn new_no_certificate_store(secure_channel: SecureChannel) -> Session {
        let max_browse_continuation_points = super::constants::MAX_BROWSE_CONTINUATION_POINTS;
        let session = Session {
            subscriptions: Subscriptions::new(100, PUBLISH_REQUEST_TIMEOUT),
            session_id: next_session_id(),
            activated: false,
            terminate_session: false,
            terminated: false,
            terminated_at: chrono::Utc::now(),
            client_certificate: None,
            security_policy_uri: String::new(),
            authentication_token: NodeId::null(),
            secure_channel: Arc::new(RwLock::new(secure_channel)),
            session_nonce: ByteString::null(),
            session_name: UAString::null(),
            session_timeout: 0f64,
            user_identity: IdentityToken::None,
            locale_ids: None,
            max_request_message_size: 0,
            max_response_message_size: 0,
            endpoint_url: UAString::null(),
            max_browse_continuation_points,
            browse_continuation_points: VecDeque::with_capacity(max_browse_continuation_points),
            can_modify_address_space: true,
            diagnostics: Arc::new(RwLock::new(ServerDiagnostics::default())),
            session_diagnostics: Arc::new(RwLock::new(SessionDiagnostics::default())),
            last_service_request_timestamp: Utc::now(),
        };
        {
            let mut diagnostics = trace_write_lock_unwrap!(session.diagnostics);
            diagnostics.on_create_session(&session);
        }
        session
    }

    /// Create a `Session` from a `Server`
    pub fn new(server: &Server) -> Session {
        let max_browse_continuation_points = super::constants::MAX_BROWSE_CONTINUATION_POINTS;

        let server_state = server.server_state();
        let server_state = trace_read_lock_unwrap!(server_state);
        let max_subscriptions = server_state.max_subscriptions;
        let diagnostics = server_state.diagnostics.clone();
        let (decoding_options, can_modify_address_space) = {
            let config = trace_read_lock_unwrap!(server_state.config);
            (
                config.decoding_options(),
                config.limits.clients_can_modify_address_space,
            )
        };

        let session = Session {
            subscriptions: Subscriptions::new(max_subscriptions, PUBLISH_REQUEST_TIMEOUT),
            session_id: next_session_id(),
            activated: false,
            terminate_session: false,
            terminated: false,
            terminated_at: chrono::Utc::now(),
            client_certificate: None,
            security_policy_uri: String::new(),
            authentication_token: NodeId::null(),
            secure_channel: Arc::new(RwLock::new(SecureChannel::new(
                server.certificate_store(),
                Role::Server,
                decoding_options,
            ))),
            session_nonce: ByteString::null(),
            session_name: UAString::null(),
            session_timeout: 0f64,
            user_identity: IdentityToken::None,
            locale_ids: None,
            max_request_message_size: 0,
            max_response_message_size: 0,
            endpoint_url: UAString::null(),
            max_browse_continuation_points,
            browse_continuation_points: VecDeque::with_capacity(max_browse_continuation_points),
            can_modify_address_space,
            diagnostics,
            session_diagnostics: Arc::new(RwLock::new(SessionDiagnostics::default())),
            last_service_request_timestamp: Utc::now(),
        };
        {
            let mut diagnostics = trace_write_lock_unwrap!(session.diagnostics);
            diagnostics.on_create_session(&session);
        }
        session
    }
    pub fn secure_channel(&self) -> Arc<RwLock<SecureChannel>> {
        self.secure_channel.clone()
    }

    pub fn session_id(&self) -> &NodeId {
        &self.session_id
    }

    pub fn set_activated(&mut self, activated: bool) {
        self.activated = activated;
    }

    pub fn is_activated(&self) -> bool {
        self.activated
    }

    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn terminated_at(&self) -> DateTimeUtc {
        self.terminated_at
    }

    pub fn set_terminated(&mut self) {
        info!("Session being set to terminated");
        self.terminated = true;
        self.terminated_at = chrono::Utc::now();
    }

    pub fn authentication_token(&self) -> &NodeId {
        &self.authentication_token
    }

    pub fn set_authentication_token(&mut self, authentication_token: NodeId) {
        self.authentication_token = authentication_token;
    }

    pub fn session_timeout(&self) -> f64 {
        self.session_timeout
    }

    pub fn set_session_timeout(&mut self, session_timeout: f64) {
        self.session_timeout = session_timeout;
    }

    pub fn set_max_request_message_size(&mut self, max_request_message_size: u32) {
        self.max_request_message_size = max_request_message_size;
    }

    pub fn set_max_response_message_size(&mut self, max_response_message_size: u32) {
        self.max_response_message_size = max_response_message_size;
    }

    pub fn endpoint_url(&self) -> &UAString {
        &self.endpoint_url
    }

    pub fn set_endpoint_url(&mut self, endpoint_url: UAString) {
        self.endpoint_url = endpoint_url;
    }

    pub fn set_security_policy_uri(&mut self, security_policy_uri: &str) {
        self.security_policy_uri = security_policy_uri.to_string();
    }

    pub fn set_user_identity(&mut self, user_identity: IdentityToken) {
        self.user_identity = user_identity;
    }

    pub fn last_service_request_timestamp(&self) -> DateTimeUtc {
        self.last_service_request_timestamp
    }

    pub fn set_last_service_request_timestamp(
        &mut self,
        last_service_request_timestamp: DateTimeUtc,
    ) {
        self.last_service_request_timestamp = last_service_request_timestamp;
    }

    pub fn locale_ids(&self) -> &Option<Vec<UAString>> {
        &self.locale_ids
    }

    pub fn set_locale_ids(&mut self, locale_ids: Option<Vec<UAString>>) {
        self.locale_ids = locale_ids;
    }

    pub fn client_certificate(&self) -> &Option<X509> {
        &self.client_certificate
    }

    pub fn set_client_certificate(&mut self, client_certificate: Option<X509>) {
        self.client_certificate = client_certificate;
    }

    pub fn session_nonce(&self) -> &ByteString {
        &self.session_nonce
    }

    pub fn set_session_nonce(&mut self, session_nonce: ByteString) {
        self.session_nonce = session_nonce;
    }

    pub fn session_name(&self) -> &UAString {
        &self.session_name
    }

    pub fn set_session_name(&mut self, session_name: UAString) {
        self.session_name = session_name;
    }

    pub(crate) fn session_diagnostics(&self) -> Arc<RwLock<SessionDiagnostics>> {
        self.session_diagnostics.clone()
    }

    pub(crate) fn subscriptions(&self) -> &Subscriptions {
        &self.subscriptions
    }

    pub(crate) fn subscriptions_mut(&mut self) -> &mut Subscriptions {
        &mut self.subscriptions
    }

    pub(crate) fn enqueue_publish_request(
        &mut self,
        now: &DateTimeUtc,
        request_id: u32,
        request: PublishRequest,
        address_space: &AddressSpace,
    ) -> Result<(), StatusCode> {
        self.subscriptions
            .enqueue_publish_request(now, request_id, request, address_space)
    }

    pub(crate) fn tick_subscriptions(
        &mut self,
        now: &DateTimeUtc,
        address_space: &AddressSpace,
        reason: TickReason,
    ) -> Result<(), StatusCode> {
        self.subscriptions.tick(now, address_space, reason)
    }

    /// Reset the lifetime counter on the subscription, e.g. because a service references the
    /// subscription.
    pub(crate) fn reset_subscription_lifetime_counter(&mut self, subscription_id: u32) {
        if let Some(subscription) = self.subscriptions.get_mut(subscription_id) {
            subscription.reset_lifetime_counter();
        }
    }

    /// Iterates through the existing queued publish requests and creates a timeout
    /// publish response any that have expired.
    pub(crate) fn expire_stale_publish_requests(&mut self, now: &DateTimeUtc) {
        self.subscriptions.expire_stale_publish_requests(now);
    }

    pub(crate) fn add_browse_continuation_point(
        &mut self,
        continuation_point: BrowseContinuationPoint,
    ) {
        // Remove excess browse continuation points
        while self.browse_continuation_points.len() >= self.max_browse_continuation_points {
            let continuation_point = self.browse_continuation_points.pop_front();
            debug!(
                "Removing old continuation point {} to make way for new one",
                continuation_point.unwrap().id.as_base64()
            );
        }
        self.browse_continuation_points
            .push_back(continuation_point);
    }

    /// Finds and REMOVES a continuation point by id.
    pub(crate) fn find_browse_continuation_point(
        &mut self,
        id: &ByteString,
    ) -> Option<BrowseContinuationPoint> {
        if let Some(idx) = self
            .browse_continuation_points
            .iter()
            .position(|continuation_point| continuation_point.id == *id)
        {
            self.browse_continuation_points.remove(idx)
        } else {
            None
        }
    }

    pub(crate) fn remove_expired_browse_continuation_points(
        &mut self,
        address_space: &AddressSpace,
    ) {
        self.browse_continuation_points.retain(|continuation_point| {
            let valid = continuation_point.is_valid_browse_continuation_point(address_space);
            if !valid {
                debug!("Continuation point {:?} is no longer valid and will be removed, address space last modified = {}", continuation_point, address_space.last_modified());
            }
            valid
        });
    }

    /// Remove all the specified continuation points by id
    pub(crate) fn remove_browse_continuation_points(&mut self, continuation_points: &[ByteString]) {
        // Turn the supplied slice into a set
        let continuation_points_set: HashSet<ByteString> =
            continuation_points.iter().cloned().collect();
        // Now remove any continuation points that are part of that set
        self.browse_continuation_points
            .retain(|continuation_point| !continuation_points_set.contains(&continuation_point.id));
    }

    pub(crate) fn can_modify_address_space(&self) -> bool {
        self.can_modify_address_space
    }

    #[cfg(test)]
    pub(crate) fn set_can_modify_address_space(&mut self, can_modify_address_space: bool) {
        self.can_modify_address_space = can_modify_address_space;
    }

    pub(crate) fn effective_user_access_level(
        &self,
        user_access_level: UserAccessLevel,
        _node_id: &NodeId,
        _attribute_id: AttributeId,
    ) -> UserAccessLevel {
        // TODO session could modify the user_access_level further here via user / groups
        user_access_level
    }

    /// Helper function to return the client user id from the identity token or None of there is no user id
    ///
    /// This conforms to OPC Part 5 6.4.3 ClientUserId
    pub fn client_user_id(&self) -> UAString {
        match self.user_identity {
            IdentityToken::None | IdentityToken::AnonymousIdentityToken(_) => UAString::null(),
            IdentityToken::UserNameIdentityToken(ref token) => token.user_name.clone(),
            IdentityToken::X509IdentityToken(ref token) => {
                if let Ok(cert) = X509::from_byte_string(&token.certificate_data) {
                    UAString::from(cert.subject_name())
                } else {
                    UAString::from("Invalid certificate")
                }
            }
            IdentityToken::Invalid(_) => UAString::from("invalid"),
        }
    }

    /// Helper function to return the secure channel id as a string
    pub fn secure_channel_id(&self) -> String {
        let secure_channel = trace_read_lock_unwrap!(self.secure_channel);
        format!("{}", secure_channel.secure_channel_id())
    }

    pub fn is_session_terminated(&self) -> bool {
        self.terminate_session
    }

    pub fn terminate_session(&mut self) {
        self.terminate_session = true;
    }

    pub(crate) fn register_session(&self, address_space: Arc<RwLock<AddressSpace>>) {
        let session_diagnostics = trace_read_lock_unwrap!(self.session_diagnostics);
        let mut address_space = trace_write_lock_unwrap!(address_space);
        session_diagnostics.register_session(self, &mut address_space);
    }

    pub(crate) fn deregister_session(&self, address_space: Arc<RwLock<AddressSpace>>) {
        let session_diagnostics = trace_read_lock_unwrap!(self.session_diagnostics);
        let mut address_space = trace_write_lock_unwrap!(address_space);
        session_diagnostics.deregister_session(self, &mut address_space);
    }
}
