use std::time::{Duration, Instant};

use crate::server::identity_token::IdentityToken;
use crate::server::prelude::{ByteString, NodeId, StatusCode, UAString, X509};

pub struct Session {
    /// The session identifier
    session_id: NodeId,
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
    /// Maximum number of continuation points
    max_browse_continuation_points: usize,

    last_service_request: Instant,

    is_activated: bool,
}

impl Session {
    pub fn validate_timed_out(&mut self) -> Result<(), StatusCode> {
        let Some(timeout) = &self.session_timeout else {
            self.last_service_request = Instant::now();
            return Ok(());
        };

        let elapsed = Instant::now() - self.last_service_request;

        self.last_service_request = Instant::now();

        if timeout > &elapsed {
            // TODO: Trigger session timeout here
            error!("Session has timed out because too much time has elapsed between service calls - elapsed time = {}ms", elapsed.as_millis());
            Err(StatusCode::BadSessionIdInvalid)
        } else {
            Ok(())
        }
    }

    pub fn validate_activated(&self) -> Result<(), StatusCode> {
        if !self.is_activated {
            Err(StatusCode::BadSessionNotActivated)
        } else {
            Ok(())
        }
    }

    pub fn validate_secure_channel_id(&self, secure_channel_id: u32) -> Result<(), StatusCode> {
        if secure_channel_id != self.secure_channel_id {
            Err(StatusCode::BadSecureChannelIdInvalid)
        } else {
            Ok(())
        }
    }
}
