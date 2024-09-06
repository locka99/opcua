use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crypto::{random, security_policy::SecurityPolicy};
use parking_lot::RwLock;
use tokio::sync::Notify;

use crate::{
    core::comms::secure_channel::SecureChannel,
    crypto,
    server::{identity_token::IdentityToken, info::ServerInfo},
    types::{
        ActivateSessionRequest, ActivateSessionResponse, CloseSessionRequest, CloseSessionResponse,
        CreateSessionRequest, CreateSessionResponse, NodeId, ResponseHeader, SignatureData,
        StatusCode,
    },
};

use super::{instance::Session, message_handler::MessageHandler};

lazy_static! {
    static ref NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);
}

pub(super) fn next_session_id() -> (NodeId, u32) {
    // Session id will be a string identifier
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    (NodeId::new(1, session_id), session_id)
}

/// Manages all sessions on the server.
pub struct SessionManager {
    sessions: HashMap<NodeId, Arc<RwLock<Session>>>,
    info: Arc<ServerInfo>,
    notify: Arc<Notify>,
}

impl SessionManager {
    pub(crate) fn new(info: Arc<ServerInfo>, notify: Arc<Notify>) -> Self {
        Self {
            sessions: Default::default(),
            info,
            notify,
        }
    }

    /// Get a session by its authentication token.
    pub fn find_by_token(&self, authentication_token: &NodeId) -> Option<Arc<RwLock<Session>>> {
        Self::find_by_token_int(&self.sessions, authentication_token)
    }

    fn find_by_token_int<'a>(
        sessions: &'a HashMap<NodeId, Arc<RwLock<Session>>>,
        authentication_token: &NodeId,
    ) -> Option<Arc<RwLock<Session>>> {
        sessions
            .iter()
            .find(|(_, s)| &s.read().authentication_token == authentication_token)
            .map(|p| p.1.clone())
    }

    pub(crate) fn create_session(
        &mut self,
        channel: &mut SecureChannel,
        certificate_store: &RwLock<crypto::CertificateStore>,
        request: &CreateSessionRequest,
    ) -> Result<CreateSessionResponse, StatusCode> {
        if self.sessions.len() >= self.info.config.limits.max_sessions {
            return Err(StatusCode::BadTooManySessions);
        }

        // TODO: Auditing and diagnostics.
        let endpoints = self
            .info
            .new_endpoint_descriptions(request.endpoint_url.as_ref());
        // TODO request.endpoint_url should match hostname of server application certificate
        // Find matching end points for this url
        if request.endpoint_url.is_null() {
            error!("Create session was passed an null endpoint url");
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        }

        let Some(endpoints) = endpoints else {
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        };

        let client_certificate = crypto::X509::from_byte_string(&request.client_certificate);
        let security_policy = channel.security_policy();

        if security_policy != SecurityPolicy::None {
            let store = trace_read_lock!(certificate_store);
            let result = match &client_certificate {
                Ok(cert) => store.validate_or_reject_application_instance_cert(
                    cert,
                    security_policy,
                    None,
                    None,
                ),
                Err(e) => *e,
            };

            if result.is_bad() {
                return Err(result);
            }
        }

        let session_timeout = self
            .info
            .config
            .max_session_timeout_ms
            .min(request.requested_session_timeout.floor() as u64);
        let max_request_message_size = self.info.config.limits.max_message_size as u32;

        let server_signature = if let Some(ref pkey) = self.info.server_pkey {
            crypto::create_signature_data(
                pkey,
                security_policy,
                &request.client_certificate,
                &request.client_nonce,
            )
            .unwrap_or_else(|err| {
                error!(
                    "Cannot create signature data from private key, check log and error {:?}",
                    err
                );
                SignatureData::null()
            })
        } else {
            SignatureData::null()
        };

        let authentication_token = NodeId::new(0, random::byte_string(32));
        let server_nonce = security_policy.random_nonce();
        let server_certificate = self.info.server_certificate_as_byte_string();
        let server_endpoints = Some(endpoints);

        let session = Session::create(
            &self.info,
            authentication_token.clone(),
            channel.secure_channel_id(),
            session_timeout,
            max_request_message_size,
            request.max_response_message_size,
            request.endpoint_url.clone(),
            security_policy.to_uri().to_string(),
            IdentityToken::None,
            client_certificate.ok(),
            server_nonce.clone(),
            request.session_name.clone(),
            request.client_description.clone(),
            channel.security_mode(),
        );

        let session_id = session.session_id().clone();
        self.sessions
            .insert(session_id.clone(), Arc::new(RwLock::new(session)));

        self.notify.notify_waiters();

        // TODO: Register session in core namespace
        // Note: This will instead be handled by the diagnostic node manager on the fly.

        Ok(CreateSessionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            session_id: session_id,
            authentication_token,
            revised_session_timeout: session_timeout as f64,
            server_nonce,
            server_certificate,
            server_endpoints,
            server_software_certificates: None,
            server_signature,
            max_request_message_size,
        })
    }

    pub(crate) async fn activate_session(
        &mut self,
        channel: &mut SecureChannel,
        request: &ActivateSessionRequest,
    ) -> Result<ActivateSessionResponse, StatusCode> {
        let Some(session) = self.find_by_token(&request.request_header.authentication_token) else {
            return Err(StatusCode::BadSessionIdInvalid);
        };

        let mut session = trace_write_lock!(session);
        session.validate_timed_out()?;

        let security_policy = channel.security_policy();
        let security_mode = channel.security_mode();
        let secure_channel_id = channel.secure_channel_id();
        let server_nonce = security_policy.random_nonce();
        let endpoint_url = session.endpoint_url().as_ref();

        if !self
            .info
            .endpoint_exists(endpoint_url, security_policy, security_mode)
        {
            error!("activate_session, Endpoint dues not exist for requested url & mode {}, {:?} / {:?}",
                endpoint_url, security_policy, security_mode);
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        }

        if security_policy != SecurityPolicy::None {
            Self::verify_client_signature(
                security_policy,
                &self.info,
                &session,
                &request.client_signature,
            )?;
        }

        let user_token = self
            .info
            .authenticate_endpoint(
                request,
                endpoint_url,
                security_policy,
                security_mode,
                &request.user_identity_token,
                session.session_nonce(),
            )
            .await?;

        if !session.is_activated() && session.secure_channel_id() != secure_channel_id {
            error!("activate session, rejected secure channel id {} for inactive session does not match one used to create session, {}", secure_channel_id, session.secure_channel_id());
            return Err(StatusCode::BadSecureChannelIdInvalid);
        } else {
            // TODO additional secure channel validation here for client certificate and user identity
            //  token
        }

        // TODO: If the user identity changed here, we need to re-check permissions for any created monitored items.
        // It may be possible to just create a "fake" UserAccessLevel for each monitored item and pass it to the auth manager.
        // The standard also mentions that a server may need to
        // "Tear down connections to an underlying system and re-establish them using the new credentials". We need some way to
        // handle this eventuality, perhaps a dedicated node-manager endpoint that can be called here.
        session.activate(
            secure_channel_id,
            server_nonce,
            IdentityToken::new(&request.user_identity_token, &self.info.decoding_options()),
            request.locale_ids.clone(),
            user_token,
        );

        // TODO: Audit

        Ok(ActivateSessionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            server_nonce: session.session_nonce().clone(),
            results: None,
            diagnostic_infos: None,
        })
    }

    fn verify_client_signature(
        security_policy: SecurityPolicy,
        info: &ServerInfo,
        session: &Session,
        client_signature: &SignatureData,
    ) -> Result<(), StatusCode> {
        if let Some(ref client_certificate) = session.client_certificate() {
            if let Some(ref server_certificate) = info.server_certificate {
                let r = crypto::verify_signature_data(
                    client_signature,
                    security_policy,
                    client_certificate,
                    server_certificate,
                    session.session_nonce().as_ref(),
                );
                if r.is_good() {
                    Ok(())
                } else {
                    Err(r)
                }
            } else {
                error!("Client signature verification failed, server has no server certificate");
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            error!("Client signature verification failed, session has no client certificate");
            Err(StatusCode::BadUnexpectedError)
        }
    }

    pub(crate) async fn close_session(
        &mut self,
        channel: &mut SecureChannel,
        handler: &mut MessageHandler,
        request: &CloseSessionRequest,
    ) -> Result<CloseSessionResponse, StatusCode> {
        let Some(session) = self.find_by_token(&request.request_header.authentication_token) else {
            return Err(StatusCode::BadSessionIdInvalid);
        };

        let session = trace_read_lock!(session);
        let id = session.session_id_numeric();
        let token = session.user_token().cloned();

        let secure_channel_id = channel.secure_channel_id();
        if !session.is_activated() && session.secure_channel_id() != secure_channel_id {
            error!("close_session rejected, secure channel id {} for inactive session does not match one used to create session, {}", secure_channel_id, session.secure_channel_id());
            return Err(StatusCode::BadSecureChannelIdInvalid);
        }
        let session_id = session.session_id().clone();

        let session = self.sessions.remove(&session_id).unwrap();
        {
            let mut session_lck = trace_write_lock!(session);
            session_lck.close();
        }

        if request.delete_subscriptions {
            handler
                .delete_session_subscriptions(id, session, token.unwrap())
                .await;
        }

        Ok(CloseSessionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
        })
    }

    pub(crate) fn expire_session(&mut self, id: &NodeId) {
        let Some(session) = self.sessions.remove(id) else {
            return;
        };

        info!("Session {id} has expired, removing it from the session map. Subscriptions will remain until they individually expire");

        let mut session = trace_write_lock!(session);
        session.close();
    }

    pub(crate) fn check_session_expiry(&self) -> (Instant, Vec<NodeId>) {
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut expiry =
            now + Duration::from_millis(self.info.config.max_session_timeout_ms as u64);
        for (id, session) in &self.sessions {
            let deadline = session.read().deadline();
            if deadline < now {
                expired.push(id.clone());
            } else if deadline < expiry {
                expiry = deadline;
            }
        }

        (expiry, expired)
    }
}
