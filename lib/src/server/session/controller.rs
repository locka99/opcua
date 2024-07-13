use std::{
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::{future::Either, stream::FuturesUnordered, Future, StreamExt};
use tokio::net::TcpStream;

use crate::{
    core::{comms::{secure_channel::SecureChannel, security_header::SecurityHeader, tcp_types::ErrorMessage}, config::Config, supported_message::SupportedMessage}, crypto::{CertificateStore, SecurityPolicy}, server::{
        authenticator::UserToken,
        info::ServerInfo,
        node_manager::NodeManagers,
        subscriptions::SubscriptionCache,
        transport::tcp::{Request, TcpTransport, TransportConfig, TransportPollResult},
    }, sync::RwLock, types::{
        ChannelSecurityToken, DateTime, FindServersResponse,
        GetEndpointsResponse, MessageSecurityMode,
        OpenSecureChannelRequest, OpenSecureChannelResponse, ResponseHeader,
        SecurityTokenRequestType, ServiceFault, StatusCode,
    }
};

use super::{instance::Session, manager::SessionManager, message_handler::MessageHandler};

pub(crate) struct Response {
    pub message: SupportedMessage,
    pub request_id: u32,
}

impl Response {
    pub fn from_result(
        result: Result<impl Into<SupportedMessage>, StatusCode>,
        request_handle: u32,
        request_id: u32,
    ) -> Self {
        match result {
            Ok(r) => Self {
                message: r.into(),
                request_id,
            },
            Err(e) => Self {
                message: ServiceFault::new(request_handle, e).into(),
                request_id,
            },
        }
    }
}

pub enum ControllerCommand {
    Close,
}

#[derive(Debug)]
enum ControllerTimeout {
    /// Controller is waiting for a client to establish a secure channel
    WaitingForChannel(Instant),
    /// Controller has an open secure channel, but no session
    OpenChannel(Instant),
    /// Controller has an open session. The deadline in this case is the smallest of the secure channel expiry and the
    /// session timeout.
    OpenSession(Instant, Instant)
}

impl ControllerTimeout {
    pub async fn timeout(&self) {
        match self {
            ControllerTimeout::WaitingForChannel(deadline) |
            ControllerTimeout::OpenChannel(deadline) => tokio::time::sleep_until((*deadline).into()).await,
            ControllerTimeout::OpenSession(channel, session) => tokio::time::sleep_until((*channel.min(session)).into()).await,
        }
    }
}

pub struct SessionController {
    channel: SecureChannel,
    transport: TcpTransport,
    secure_channel_state: SecureChannelState,
    session_manager: Arc<RwLock<SessionManager>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    message_handler: MessageHandler,
    pending_messages: FuturesUnordered<
        Pin<Box<dyn Future<Output = Result<Response, String>> + Send + Sync + 'static>>,
    >,
    info: Arc<ServerInfo>,
    deadline: ControllerTimeout,
}

enum RequestProcessResult {
    Ok,
    Close,
}

impl SessionController {
    pub fn new(
        socket: TcpStream,
        session_manager: Arc<RwLock<SessionManager>>,
        certificate_store: Arc<RwLock<CertificateStore>>,
        info: Arc<ServerInfo>,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Self {
        let channel = SecureChannel::new(
            certificate_store.clone(),
            crate::core::comms::secure_channel::Role::Server,
            info.decoding_options(),
        );
        let transport = TcpTransport::new(
            socket,
            TransportConfig {
                send_buffer_size: info.config.limits.send_buffer_size,
                max_message_size: info.config.limits.max_message_size,
                max_chunk_count: info.config.limits.max_chunk_count,
                hello_timeout: Duration::from_secs(info.config.tcp_config.hello_timeout as u64),
            },
            info.decoding_options(),
            info.clone(),
        );

        Self {
            channel,
            transport,
            secure_channel_state: SecureChannelState::new(),
            session_manager,
            certificate_store,
            message_handler: MessageHandler::new(info.clone(), node_managers, subscriptions),
            deadline: ControllerTimeout::WaitingForChannel(Instant::now() + Duration::from_secs(info.config.tcp_config.hello_timeout as u64)),
            info,
            pending_messages: FuturesUnordered::new(),
        }
    }

    pub async fn run(mut self, mut command: tokio::sync::mpsc::Receiver<ControllerCommand>) {
        loop {
            let resp_fut = if self.pending_messages.is_empty() {
                Either::Left(futures::future::pending::<Option<Result<Response, String>>>())
            } else {
                Either::Right(self.pending_messages.next())
            };

            tokio::select! {
                _ = self.deadline.timeout() => {
                    if !self.transport.is_closing() {
                        warn!("Connection timed out, closing");
                        self.transport.enqueue_error(ErrorMessage::new(StatusCode::BadTimeout, "Connection timeout"));
                    }
                    self.transport.set_closing();
                }
                cmd = command.recv() => {
                    match cmd {
                        Some(ControllerCommand::Close) | None => {
                            if !self.transport.is_closing() {
                                self.transport.enqueue_error(ErrorMessage::new(StatusCode::BadServerHalted, "Server stopped"));
                            }
                            self.transport.set_closing();
                        }
                    }
                }
                msg = resp_fut => {
                    let msg = match msg {
                        Some(Ok(x)) => x,
                        Some(Err(e)) => {
                            error!("Unexpected error in message handler: {e}");
                            self.transport.set_closing();
                            continue;
                        }
                        // Cannot happen, pending_messages is non-empty or this future never returns.
                        None => unreachable!(),
                    };
                    if let Err(e) = self.transport.enqueue_message_for_send(
                        &mut self.channel,
                        msg.message,
                        msg.request_id
                    ) {
                        error!("Failed to send response: {e}");
                        self.transport.set_closing();
                    }
                }
                res = self.transport.poll(&mut self.channel) => {
                    trace!("Transport poll result: {res:?}");
                    match res {
                        TransportPollResult::IncomingMessage(req) => {
                            if matches!(self.process_request(req).await, RequestProcessResult::Close) {
                                self.transport.set_closing();
                            }
                        }
                        TransportPollResult::Error(s) => {
                            error!("Fatal transport error: {s}");
                            if !self.transport.is_closing() {
                                self.transport.enqueue_error(ErrorMessage::new(s, "Transport error"));
                            }
                            self.transport.set_closing();
                        }
                        TransportPollResult::Closed => break,
                        _ => (),
                    }
                }
            }
        }
    }

    async fn process_request(&mut self, req: Request) -> RequestProcessResult {
        let id = req.request_id;
        match req.message {
            SupportedMessage::OpenSecureChannelRequest(r) => {
                let res = self.open_secure_channel(
                    &req.chunk_info.security_header,
                    self.transport.client_protocol_version,
                    &r,
                );
                if res.is_ok() {
                    match &mut self.deadline {
                        ControllerTimeout::OpenSession(chan, _) => *chan = self.channel.token_renewal_deadline(),
                        s => *s = ControllerTimeout::OpenChannel(self.channel.token_renewal_deadline()),
                    }
                }
                match res {
                    Ok(r) => match self
                        .transport
                        .enqueue_message_for_send(&mut self.channel, r, id)
                    {
                        Ok(_) => RequestProcessResult::Ok,
                        Err(e) => {
                            error!("Failed to send open secure channel response: {e}");
                            return RequestProcessResult::Close;
                        }
                    },
                    Err(e) => {
                        let _ = self.transport.enqueue_message_for_send(
                            &mut self.channel,
                            ServiceFault::new(&r.request_header, e).into(),
                            id,
                        );
                        return RequestProcessResult::Close;
                    }
                }
            }

            SupportedMessage::CloseSecureChannelRequest(_r) => {
                return RequestProcessResult::Close;
            }

            SupportedMessage::CreateSessionRequest(request) => {
                let mut mgr = trace_write_lock!(self.session_manager);
                let res = mgr.create_session(&mut self.channel, &self.certificate_store, &request);
                drop(mgr);
                self.process_service_result(res, request.request_header.request_handle, id)
            }

            SupportedMessage::ActivateSessionRequest(request) => {
                let mut mgr = trace_write_lock!(self.session_manager);
                let res = mgr.activate_session(&mut self.channel, &request).await;
                drop(mgr);
                self.process_service_result(res, request.request_header.request_handle, id)
            }

            SupportedMessage::CloseSessionRequest(request) => {
                let mut mgr = trace_write_lock!(self.session_manager);
                let res = mgr
                    .close_session(&mut self.channel, &mut self.message_handler, &request)
                    .await;
                drop(mgr);
                self.process_service_result(res, request.request_header.request_handle, id)
            }
            SupportedMessage::GetEndpointsRequest(request) => {
                // TODO some of the arguments in the request are ignored
                //  localeIds - list of locales to use for human readable strings (in the endpoint descriptions)

                // TODO audit - generate event for failed service invocation

                let endpoints = self
                    .info
                    .endpoints(&request.endpoint_url, &request.profile_uris);
                self.process_service_result(
                    Ok(GetEndpointsResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        endpoints,
                    }),
                    request.request_header.request_handle,
                    id,
                )
            }
            SupportedMessage::FindServersRequest(request) => {
                let desc = self.info.config.application_description();
                let mut servers = vec![desc];

                // TODO endpoint URL

                // TODO localeids, filter out servers that do not support locale ids

                // Filter servers that do not have a matching application uri
                if let Some(ref server_uris) = request.server_uris {
                    if !server_uris.is_empty() {
                        // Filter the servers down
                        servers.retain(|server| {
                            server_uris.iter().any(|uri| *uri == server.application_uri)
                        });
                    }
                }

                let servers = Some(servers);

                self.process_service_result(
                    Ok(FindServersResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        servers,
                    }),
                    request.request_header.request_handle,
                    id,
                )
            }

            message => {
                let now = Instant::now();
                let mgr = trace_read_lock!(self.session_manager);
                let session = mgr.find_by_token(&message.request_header().authentication_token);

                let (session_id, session, user_token) = match Self::validate_request(
                    &message,
                    self.channel.secure_channel_id(),
                    session,
                    &mut self.deadline
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        match self
                            .transport
                            .enqueue_message_for_send(&mut self.channel, e, id)
                        {
                            Ok(_) => return RequestProcessResult::Ok,
                            Err(e) => {
                                error!("Failed to send request response: {e}");
                                return RequestProcessResult::Close;
                            }
                        }
                    }
                };
                let deadline = {
                    let timeout = message.request_header().timeout_hint;
                    let max_timeout = self.info.config.max_timeout_ms;
                    let timeout = if max_timeout == 0 {
                        timeout
                    } else {
                        max_timeout.max(timeout)
                    };
                    if timeout == 0 {
                        // Just set some huge value. A request taking a day can probably
                        // be safely canceled...
                        now + Duration::from_secs(60 * 60 * 24)
                    } else {
                        now + Duration::from_millis(timeout.into())
                    }
                };
                let request_handle = message.request_handle();

                match self
                    .message_handler
                    .handle_message(message, session_id, session, user_token, id)
                {
                    super::message_handler::HandleMessageResult::AsyncMessage(mut handle) => {
                        self.pending_messages
                            .push(Box::pin(async move {
                                // Select biased because if for some reason there's a long time between polls,
                                // we want to return the response even if the timeout expired. We only want to send a timeout
                                // if the call has not been finished yet.
                                tokio::select! {
                                    biased;
                                    r = &mut handle => {
                                        r.map_err(|e| e.to_string())
                                    }
                                    _ = tokio::time::sleep_until(deadline.into()) => {
                                        handle.abort();
                                        Ok(Response { message: ServiceFault::new(request_handle, StatusCode::BadTimeout).into(), request_id: id })
                                    }
                                    
                                }
                            }));
                        RequestProcessResult::Ok
                    }
                    super::message_handler::HandleMessageResult::SyncMessage(s) => {
                        if let Err(e) = self.transport.enqueue_message_for_send(
                            &mut self.channel,
                            s.message,
                            s.request_id,
                        ) {
                            error!("Failed to send response: {e}");
                            return RequestProcessResult::Close;
                        }
                        RequestProcessResult::Ok
                    }
                    super::message_handler::HandleMessageResult::PublishResponse(resp) => {
                        self.pending_messages.push(Box::pin(resp.recv()));
                        RequestProcessResult::Ok
                    }
                }
            }
        }
    }

    fn process_service_result(
        &mut self,
        res: Result<impl Into<SupportedMessage>, StatusCode>,
        request_handle: u32,
        request_id: u32,
    ) -> RequestProcessResult {
        let message = match res {
            Ok(m) => m.into(),
            Err(e) => ServiceFault::new(request_handle, e).into(),
        };
        if let Err(e) =
            self.transport
                .enqueue_message_for_send(&mut self.channel, message, request_id)
        {
            error!("Failed to send request response: {e}");
            RequestProcessResult::Close
        } else {
            RequestProcessResult::Ok
        }
    }

    fn validate_request(
        message: &SupportedMessage,
        channel_id: u32,
        session: Option<Arc<RwLock<Session>>>,
        timeout: &mut ControllerTimeout,
    ) -> Result<(u32, Arc<RwLock<Session>>, UserToken), SupportedMessage> {
        let header = message.request_header();

        let Some(session) = session else {
            return Err(ServiceFault::new(header, StatusCode::BadSessionIdInvalid).into());
        };

        let session_lock = trace_read_lock!(session);
        let id = session_lock.session_id_numeric();

        

        let user_token = (move || {
            let token = session_lock.validate_activated()?;
            session_lock.validate_secure_channel_id(channel_id)?;
            session_lock.validate_timed_out()?;
            match timeout {
                ControllerTimeout::OpenSession(_, sess) => *sess = session_lock.deadline(),
                // Should be unreachable.
                r => *r = ControllerTimeout::OpenSession(session_lock.deadline(), session_lock.deadline()),
            }
            Ok(token.clone())
        })()
        .map_err(|e| ServiceFault::new(header, e).into())?;
        Ok((id, session, user_token))
    }

    fn open_secure_channel(
        &mut self,
        security_header: &SecurityHeader,
        client_protocol_version: u32,
        request: &OpenSecureChannelRequest,
    ) -> Result<SupportedMessage, StatusCode> {
        let security_header = match security_header {
            SecurityHeader::Asymmetric(security_header) => security_header,
            _ => {
                error!("Secure channel request message does not have asymmetric security header");
                return Err(StatusCode::BadUnexpectedError);
            }
        };

        // Must compare protocol version to the one from HELLO
        if request.client_protocol_version != client_protocol_version {
            error!(
                "Client sent a different protocol version than it did in the HELLO - {} vs {}",
                request.client_protocol_version, client_protocol_version
            );
            return Ok(ServiceFault::new(
                &request.request_header,
                StatusCode::BadProtocolVersionUnsupported,
            )
            .into());
        }

        // Test the request type
        let secure_channel_id = match request.request_type {
            SecurityTokenRequestType::Issue => {
                trace!("Request type == Issue");
                // check to see if renew has been called before or not
                if self.secure_channel_state.renew_count > 0 {
                    error!("Asked to issue token on session that has called renew before");
                }
                self.secure_channel_state.create_secure_channel_id()
            }
            SecurityTokenRequestType::Renew => {
                trace!("Request type == Renew");

                // Check for a duplicate nonce. It is invalid for the renew to use the same nonce
                // as was used for last issue/renew. It doesn't matter when policy is none.
                if self.channel.security_policy() != SecurityPolicy::None
                    && request.client_nonce.as_ref() == self.channel.remote_nonce()
                {
                    error!("Client reused a nonce for a renew");
                    return Ok(ServiceFault::new(
                        &request.request_header,
                        StatusCode::BadNonceInvalid,
                    )
                    .into());
                }

                // check to see if the secure channel has been issued before or not
                if !self.secure_channel_state.issued {
                    error!("Asked to renew token on session that has never issued token");
                    return Err(StatusCode::BadUnexpectedError);
                }
                self.secure_channel_state.renew_count += 1;
                self.channel.secure_channel_id()
            }
        };

        // Check the requested security mode
        debug!("Message security mode == {:?}", request.security_mode);
        match request.security_mode {
            MessageSecurityMode::None
            | MessageSecurityMode::Sign
            | MessageSecurityMode::SignAndEncrypt => {
                // TODO validate NONCE
            }
            _ => {
                error!("Security mode is invalid");
                return Ok(ServiceFault::new(
                    &request.request_header,
                    StatusCode::BadSecurityModeRejected,
                )
                .into());
            }
        }

        // Process the request
        self.secure_channel_state.issued = true;

        // Create a new secure channel info
        let security_mode = request.security_mode;
        self.channel.set_security_mode(security_mode);
        self.channel
            .set_token_id(self.secure_channel_state.create_token_id());
        self.channel.set_secure_channel_id(secure_channel_id);
        self.channel
            .set_remote_cert_from_byte_string(&security_header.sender_certificate)?;

        let revised_lifetime = self.info.config.max_secure_channel_token_lifetime_ms
            .min(request.requested_lifetime);
        self.channel.set_token_lifetime(revised_lifetime);

        match self
            .channel
            .set_remote_nonce_from_byte_string(&request.client_nonce)
        {
            Ok(_) => self.channel.create_random_nonce(),
            Err(err) => {
                error!("Was unable to set their nonce, check logic");
                return Ok(ServiceFault::new(&request.request_header, err).into());
            }
        }

        let security_policy = self.channel.security_policy();
        if security_policy != SecurityPolicy::None
            && (security_mode == MessageSecurityMode::Sign
                || security_mode == MessageSecurityMode::SignAndEncrypt)
        {
            self.channel.derive_keys();
        }

        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: self.channel.secure_channel_id(),
                token_id: self.channel.token_id(),
                created_at: DateTime::now(),
                revised_lifetime,
            },
            server_nonce: self.channel.local_nonce_as_byte_string(),
        };
        Ok(response.into())
    }
}

struct SecureChannelState {
    // Issued flag
    issued: bool,
    // Renew count, debugging
    renew_count: usize,
    // Last secure channel id
    last_secure_channel_id: u32,
    /// Last token id number
    last_token_id: u32,
}

impl SecureChannelState {
    pub fn new() -> SecureChannelState {
        SecureChannelState {
            last_secure_channel_id: 0,
            issued: false,
            renew_count: 0,
            last_token_id: 0,
        }
    }

    pub fn create_secure_channel_id(&mut self) -> u32 {
        self.last_secure_channel_id += 1;
        self.last_secure_channel_id
    }

    pub fn create_token_id(&mut self) -> u32 {
        self.last_token_id += 1;
        self.last_token_id
    }
}
