use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use super::continuation_points::ContinuationPoint;
use super::manager::next_session_id;
use crate::async_server::authenticator::UserToken;
use crate::async_server::constants;
use crate::async_server::identity_token::IdentityToken;
use crate::async_server::info::ServerInfo;
use crate::async_server::node_manager::{BrowseContinuationPoint, QueryContinuationPoint};
use crate::server::prelude::{
    ApplicationDescription, ByteString, MessageSecurityMode, NodeId, StatusCode, UAString, X509,
};

pub struct Session {
    /// The session identifier
    session_id: NodeId,
    /// For convenience, the integer form of the session ID.
    session_id_numeric: u32,
    /// Security policy
    security_policy_uri: String,
    /// Secure channel id
    secure_channel_id: u32,
    /// Client's certificate
    client_certificate: Option<X509>,
    /// Authentication token for the session
    pub(super) authentication_token: NodeId,
    /// Session nonce
    session_nonce: ByteString,
    /// Session name (supplied by client)
    session_name: UAString,
    /// Session timeout
    session_timeout: Option<Duration>,
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
    /// Maximum number of continuation points for browse
    max_browse_continuation_points: usize,
    /// Maximum number of continuation points for history.
    max_history_continuation_points: usize,
    /// Maximum number of continuation points for query.
    max_query_continuation_points: usize,
    /// Client application description
    application_description: ApplicationDescription,
    /// Message security mode. Set on the channel, but cached here.
    message_security_mode: MessageSecurityMode,
    /// Time of last service request.
    last_service_request: ArcSwap<Instant>,
    /// Continuation points for browse.
    browse_continuation_points: HashMap<ByteString, BrowseContinuationPoint>,
    /// Continuation points for history.
    history_continuation_points: HashMap<ByteString, ContinuationPoint>,
    /// Continuation points for querying.
    query_continuation_points: HashMap<ByteString, QueryContinuationPoint>,
    /// User token.
    user_token: Option<UserToken>,
}

impl Session {
    pub fn create(
        info: &ServerInfo,
        authentication_token: NodeId,
        secure_channel_id: u32,
        session_timeout: f64,
        max_request_message_size: u32,
        max_response_message_size: u32,
        endpoint_url: UAString,
        security_policy_uri: String,
        user_identity: IdentityToken,
        client_certificate: Option<X509>,
        session_nonce: ByteString,
        session_name: UAString,
        application_description: ApplicationDescription,
        message_security_mode: MessageSecurityMode,
    ) -> Self {
        let (session_id, session_id_numeric) = next_session_id();
        Self {
            session_id,
            session_id_numeric,
            security_policy_uri,
            secure_channel_id,
            client_certificate,
            authentication_token,
            session_nonce,
            session_name,
            session_timeout: Some(if session_timeout <= 0.0 {
                Duration::from_millis(constants::MAX_SESSION_TIMEOUT as u64)
            } else {
                Duration::from_millis(session_timeout as u64)
            }),
            last_service_request: ArcSwap::new(Arc::new(Instant::now())),
            user_identity,
            locale_ids: None,
            max_request_message_size,
            max_response_message_size,
            endpoint_url,
            max_browse_continuation_points: constants::MAX_BROWSE_CONTINUATION_POINTS,
            max_history_continuation_points: constants::MAX_HISTORY_CONTINUATION_POINTS,
            max_query_continuation_points: constants::MAX_QUERY_CONTINUATION_POINTS,
            browse_continuation_points: Default::default(),
            history_continuation_points: Default::default(),
            query_continuation_points: Default::default(),
            user_token: None,
            application_description,
            message_security_mode,
        }
    }

    pub fn validate_timed_out(&self) -> Result<(), StatusCode> {
        let Some(timeout) = &self.session_timeout else {
            self.last_service_request.store(Arc::new(Instant::now()));
            return Ok(());
        };

        let elapsed = Instant::now() - **self.last_service_request.load();

        self.last_service_request.store(Arc::new(Instant::now()));

        if timeout < &elapsed {
            // This will eventually be collected by the timeout monitor.
            error!("Session has timed out because too much time has elapsed between service calls - elapsed time = {}ms", elapsed.as_millis());
            Err(StatusCode::BadSessionIdInvalid)
        } else {
            Ok(())
        }
    }

    pub fn validate_activated(&self) -> Result<&UserToken, StatusCode> {
        if let Some(token) = &self.user_token {
            Ok(token)
        } else {
            Err(StatusCode::BadSessionNotActivated)
        }
    }

    pub fn validate_secure_channel_id(&self, secure_channel_id: u32) -> Result<(), StatusCode> {
        if secure_channel_id != self.secure_channel_id {
            Err(StatusCode::BadSecureChannelIdInvalid)
        } else {
            Ok(())
        }
    }

    pub fn activate(
        &mut self,
        secure_channel_id: u32,
        server_nonce: ByteString,
        identity: IdentityToken,
        locale_ids: Option<Vec<UAString>>,
        user_token: UserToken,
    ) {
        self.user_token = Some(user_token);
        self.secure_channel_id = secure_channel_id;
        self.session_nonce = server_nonce;
        self.user_identity = identity;
        self.locale_ids = locale_ids;
    }

    pub fn session_id(&self) -> &NodeId {
        &self.session_id
    }

    pub fn endpoint_url(&self) -> &UAString {
        &self.endpoint_url
    }

    pub fn client_certificate(&self) -> Option<&X509> {
        self.client_certificate.as_ref()
    }

    pub fn session_nonce(&self) -> &ByteString {
        &self.session_nonce
    }

    pub fn is_activated(&self) -> bool {
        self.user_token.is_some()
    }

    pub fn secure_channel_id(&self) -> u32 {
        self.secure_channel_id
    }

    pub(crate) fn add_browse_continuation_point(
        &mut self,
        cp: BrowseContinuationPoint,
    ) -> Result<(), ()> {
        if self.max_browse_continuation_points <= self.browse_continuation_points.len()
            && self.max_browse_continuation_points > 0
        {
            Err(())
        } else {
            self.browse_continuation_points.insert(cp.id.clone(), cp);
            Ok(())
        }
    }

    pub(crate) fn remove_browse_continuation_point(
        &mut self,
        id: &ByteString,
    ) -> Option<BrowseContinuationPoint> {
        self.browse_continuation_points.remove(id)
    }

    pub(crate) fn add_history_continuation_point(
        &mut self,
        id: &ByteString,
        cp: ContinuationPoint,
    ) -> Result<(), ()> {
        if self.max_history_continuation_points <= self.history_continuation_points.len()
            && self.max_history_continuation_points > 0
        {
            Err(())
        } else {
            self.history_continuation_points.insert(id.clone(), cp);
            Ok(())
        }
    }

    pub(crate) fn remove_history_continuation_point(
        &mut self,
        id: &ByteString,
    ) -> Option<ContinuationPoint> {
        self.history_continuation_points.remove(id)
    }

    pub(crate) fn add_query_continuation_point(
        &mut self,
        id: &ByteString,
        cp: QueryContinuationPoint,
    ) -> Result<(), ()> {
        if self.max_query_continuation_points <= self.query_continuation_points.len()
            && self.max_query_continuation_points > 0
        {
            Err(())
        } else {
            self.query_continuation_points.insert(id.clone(), cp);
            Ok(())
        }
    }

    pub(crate) fn remove_query_continuation_point(
        &mut self,
        id: &ByteString,
    ) -> Option<QueryContinuationPoint> {
        self.query_continuation_points.remove(id)
    }

    pub fn application_description(&self) -> &ApplicationDescription {
        &self.application_description
    }

    pub fn user_token(&self) -> Option<&UserToken> {
        self.user_token.as_ref()
    }

    pub fn message_security_mode(&self) -> MessageSecurityMode {
        self.message_security_mode
    }

    pub fn session_id_numeric(&self) -> u32 {
        self.session_id_numeric
    }
}
