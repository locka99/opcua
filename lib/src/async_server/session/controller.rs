use std::{sync::Arc, time::Duration};

use futures::{future::Either, stream::FuturesUnordered, StreamExt};
use tokio::{
    net::TcpStream,
    task::{JoinError, JoinHandle},
};

use crate::{
    async_server::{
        info::ServerInfo,
        transport::tcp::{Request, TcpTransport, TransportConfig, TransportPollResult},
    },
    core::config::Config,
    server::prelude::{
        CertificateStore, ChannelSecurityToken, DateTime, ErrorMessage, FindServersResponse,
        GetEndpointsResponse, MessageHeader, MessageSecurityMode, MessageType,
        OpenSecureChannelRequest, OpenSecureChannelResponse, ResponseHeader, SecureChannel,
        SecurityHeader, SecurityPolicy, SecurityTokenRequestType, ServiceFault, StatusCode,
        SupportedMessage,
    },
    sync::RwLock,
};

use super::{
    instance::Session,
    manager::SessionManager,
    message_handler::{HandleMessageResult, MessageHandler},
};

pub(super) struct Response {
    pub message: SupportedMessage,
    pub request_id: u32,
    pub request_handle: u32,
}

pub struct SessionController {
    channel: SecureChannel,
    transport: TcpTransport,
    secure_channel_state: SecureChannelState,
    session_manager: Arc<RwLock<SessionManager>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    message_handler: MessageHandler,
    pending_messages: FuturesUnordered<JoinHandle<Response>>,
    info: Arc<ServerInfo>,
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
    ) -> Self {
        let channel = SecureChannel::new(
            certificate_store.clone(),
            crate::server::prelude::Role::Server,
            info.decoding_options(),
        );
        // TODO
        let transport = TcpTransport::new(
            socket,
            TransportConfig {
                send_buffer_size: 65536,
                recv_buffer_size: 65536,
                max_message_size: 65536 * 16,
                max_chunk_count: 16,
                hello_timeout: Duration::from_secs(60),
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
            message_handler: MessageHandler::new(info.clone()),
            info,
            pending_messages: FuturesUnordered::new(),
        }
    }

    pub async fn run(mut self) {
        let mut is_closing = false;
        loop {
            let resp_fut = if self.pending_messages.is_empty() {
                Either::Left(futures::future::pending::<
                    Option<Result<Response, JoinError>>,
                >())
            } else {
                Either::Right(self.pending_messages.next())
            };

            tokio::select! {
                msg = resp_fut => {
                    let msg = match msg {
                        Some(Ok(x)) => x,
                        Some(Err(e)) => {
                            error!("Unexpected error in message handler: {e}");
                            is_closing = true;
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
                        is_closing = true;
                    }
                }
                res = self.transport.poll(&mut self.channel, is_closing) => {
                    trace!("Transport poll result: {res:?}");
                    match res {
                        TransportPollResult::IncomingMessage(req) => {
                            is_closing |= matches!(self.process_request(req), RequestProcessResult::Close);
                        }
                        TransportPollResult::Error(s) => {
                            if !is_closing {
                                self.transport.enqueue_error(ErrorMessage {
                                    message_header: MessageHeader::new(MessageType::Error),
                                    error: s.bits(),
                                    reason: "Transport error".into(),
                                });
                            }
                            is_closing = true;
                        }
                        TransportPollResult::Closed => break,
                        _ => (),
                    }
                }
            }
        }
    }

    fn process_request(&mut self, req: Request) -> RequestProcessResult {
        let id = req.request_id;
        match req.message {
            SupportedMessage::OpenSecureChannelRequest(r) => {
                let res = self.open_secure_channel(
                    &req.chunk_info.security_header,
                    self.transport.client_protocol_version,
                    &r,
                );
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
                let res = mgr.activate_session(&mut self.channel, &request);
                drop(mgr);
                self.process_service_result(res, request.request_header.request_handle, id)
            }

            SupportedMessage::CloseSessionRequest(request) => {
                let mut mgr = trace_write_lock!(self.session_manager);
                let res = mgr.close_session(&mut self.channel, &request);
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
                let mgr = trace_read_lock!(self.session_manager);
                let session = mgr.find_by_token(&message.request_header().authentication_token);

                let session = match Self::validate_request(
                    &message,
                    self.channel.secure_channel_id(),
                    session,
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

                match self.message_handler.handle_message(message, session, id) {
                    super::message_handler::HandleMessageResult::AsyncMessage(handle) => {
                        self.pending_messages.push(handle);
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

    fn validate_request<'a>(
        message: &SupportedMessage,
        channel_id: u32,
        session: Option<&'a Session>,
    ) -> Result<&'a Session, SupportedMessage> {
        let header = message.request_header();

        let Some(session) = session else {
            return Err(ServiceFault::new(header, StatusCode::BadSessionIdInvalid).into());
        };

        (move || {
            session.validate_activated()?;
            session.validate_secure_channel_id(channel_id)?;
            session.validate_timed_out()?;
            Ok(session)
        })()
        .map_err(|e| ServiceFault::new(header, e).into())
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
                revised_lifetime: request.requested_lifetime,
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
