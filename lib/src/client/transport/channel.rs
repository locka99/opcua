use std::{str::FromStr, sync::Arc};

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::{
    sync::{mpsc, Mutex},
    time::{sleep, Duration},
};

use crate::{
    client::{
        retry::SessionRetryPolicy,
        session::SessionInfo,
        transport::core::TransportPollResult,
        transport::{
            tcp::{TcpTransport, TransportConfiguration},
            OutgoingMessage,
        },
    },
    core::{
        comms::secure_channel::{Role, SecureChannel},
        supported_message::SupportedMessage,
    },
    crypto::{CertificateStore, SecurityPolicy},
    sync::RwLock,
    types::{
        ByteString, CloseSecureChannelRequest, DecodingOptions, NodeId, RequestHeader,
        SecurityTokenRequestType, StatusCode,
    },
};

use super::state::{Request, RequestSend, SecureChannelState};

/// Wrapper around an open secure channel
pub struct AsyncSecureChannel {
    session_info: SessionInfo,
    session_retry_policy: SessionRetryPolicy,
    pub(crate) secure_channel: Arc<RwLock<SecureChannel>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    transport_config: TransportConfiguration,
    state: SecureChannelState,
    issue_channel_lock: Mutex<()>,

    request_send: ArcSwapOption<RequestSend>,
}

pub struct SecureChannelEventLoop {
    transport: TcpTransport,
}

impl SecureChannelEventLoop {
    pub async fn poll(&mut self) -> TransportPollResult {
        self.transport.poll().await
    }
}

impl AsyncSecureChannel {
    pub fn new(
        certificate_store: Arc<RwLock<CertificateStore>>,
        session_info: SessionInfo,
        session_retry_policy: SessionRetryPolicy,
        decoding_options: DecodingOptions,
        ignore_clock_skew: bool,
        auth_token: Arc<ArcSwap<NodeId>>,
        transport_config: TransportConfiguration,
    ) -> Self {
        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(
            certificate_store.clone(),
            Role::Client,
            decoding_options,
        )));

        Self {
            transport_config,
            issue_channel_lock: Mutex::new(()),
            state: SecureChannelState::new(ignore_clock_skew, secure_channel.clone(), auth_token),
            session_info,
            secure_channel,
            certificate_store,
            session_retry_policy,
            request_send: Default::default(),
        }
    }

    pub async fn send(
        &self,
        request: impl Into<SupportedMessage>,
        timeout: Duration,
    ) -> Result<SupportedMessage, StatusCode> {
        let sender = self.request_send.load().as_deref().cloned();
        let Some(send) = sender else {
            return Err(StatusCode::BadNotConnected);
        };

        let should_renew_security_token = {
            let secure_channel = trace_read_lock!(self.secure_channel);
            secure_channel.should_renew_security_token()
        };

        if should_renew_security_token {
            // Grab the lock, then check again whether we should renew the secure channel,
            // this avoids renewing it multiple times if the client sends many requests in quick
            // succession.
            // Also, if the channel is currently being renewed, we need to wait for the new security token.
            let guard = self.issue_channel_lock.lock().await;
            let should_renew_security_token = {
                let secure_channel = trace_read_lock!(self.secure_channel);
                secure_channel.should_renew_security_token()
            };

            if should_renew_security_token {
                let request = self.state.begin_issue_or_renew_secure_channel(
                    SecurityTokenRequestType::Renew,
                    Duration::from_secs(30),
                    send.clone(),
                );

                let resp = request.send().await?;

                self.state.end_issue_or_renew_secure_channel(resp)?;
            }

            drop(guard);
        }

        Request::new(request, send, timeout).send().await
    }

    pub async fn connect(&self) -> Result<SecureChannelEventLoop, StatusCode> {
        self.request_send.store(None);
        loop {
            let mut backoff = self.session_retry_policy.new_backoff();
            match self.connect_no_retry().await {
                Ok(event_loop) => {
                    break Ok(event_loop);
                }
                Err(s) => {
                    let Some(delay) = backoff.next() else {
                        break Err(s);
                    };

                    sleep(delay).await
                }
            }
        }
    }

    pub(crate) fn make_request_header(&self, timeout: Duration) -> RequestHeader {
        self.state.make_request_header(timeout)
    }

    pub(crate) fn client_nonce(&self) -> ByteString {
        let secure_channel = trace_read_lock!(self.secure_channel);
        secure_channel.local_nonce_as_byte_string()
    }

    pub(crate) fn update_from_created_session(
        &self,
        nonce: &ByteString,
        certificate: &ByteString,
    ) -> Result<(), StatusCode> {
        let mut secure_channel = trace_write_lock!(self.secure_channel);
        secure_channel.set_remote_nonce_from_byte_string(nonce)?;
        secure_channel.set_remote_cert_from_byte_string(certificate)?;
        Ok(())
    }

    pub(crate) fn security_policy(&self) -> SecurityPolicy {
        let secure_channel = trace_read_lock!(self.secure_channel);
        secure_channel.security_policy()
    }

    pub async fn connect_no_retry(&self) -> Result<SecureChannelEventLoop, StatusCode> {
        {
            let mut secure_channel = trace_write_lock!(self.secure_channel);
            secure_channel.clear_security_token();
        }

        let (mut transport, send) = self.create_transport().await?;

        let request = self.state.begin_issue_or_renew_secure_channel(
            SecurityTokenRequestType::Issue,
            Duration::from_secs(30),
            send.clone(),
        );

        let request_fut = request.send();
        tokio::pin!(request_fut);

        // Temporarily poll the transport task while we're waiting for a response.
        let resp = loop {
            tokio::select! {
                r = &mut request_fut => break r?,
                r = transport.poll() => {
                    if let TransportPollResult::Closed(e) = r {
                        return Err(e);
                    }
                }
            }
        };

        self.request_send.store(Some(Arc::new(send)));
        self.state.end_issue_or_renew_secure_channel(resp)?;

        Ok(SecureChannelEventLoop { transport })
    }

    async fn create_transport(
        &self,
    ) -> Result<(TcpTransport, mpsc::Sender<OutgoingMessage>), StatusCode> {
        let endpoint_url = self.session_info.endpoint.endpoint_url.clone();
        info!("Connect");
        let security_policy =
            SecurityPolicy::from_str(self.session_info.endpoint.security_policy_uri.as_ref())
                .unwrap();

        if security_policy == SecurityPolicy::Unknown {
            error!(
                "connect, security policy \"{}\" is unknown",
                self.session_info.endpoint.security_policy_uri.as_ref()
            );
            return Err(StatusCode::BadSecurityPolicyRejected);
        }

        let (cert, key) = {
            let certificate_store = trace_write_lock!(self.certificate_store);
            certificate_store.read_own_cert_and_pkey_optional()
        };

        {
            let mut secure_channel = trace_write_lock!(self.secure_channel);
            secure_channel.set_private_key(key);
            secure_channel.set_cert(cert);
            secure_channel.set_security_policy(security_policy);
            secure_channel.set_security_mode(self.session_info.endpoint.security_mode);
            let _ = secure_channel
                .set_remote_cert_from_byte_string(&self.session_info.endpoint.server_certificate);
            debug!("security policy = {:?}", security_policy);
            debug!(
                "security mode = {:?}",
                self.session_info.endpoint.security_mode
            );
        }

        let (send, recv) = mpsc::channel(self.transport_config.max_inflight);
        let transport = TcpTransport::connect(
            self.secure_channel.clone(),
            recv,
            self.transport_config.clone(),
            endpoint_url.as_ref(),
        )
        .await?;

        Ok((transport, send))
    }

    /// Close the secure channel, optionally wait for the channel to close.
    pub async fn close_channel(&self) {
        let msg = CloseSecureChannelRequest {
            request_header: self.state.make_request_header(Duration::from_secs(60)),
        };

        let sender = self.request_send.load().as_deref().cloned();
        let request = sender.map(|s| Request::new(msg, s, Duration::from_secs(60)));

        // Instruct the channel to not attempt to reopen.
        if let Some(request) = request {
            if let Err(e) = request.send_no_response().await {
                error!("Failed to send disconnect message, queue full: {e}");
            }
        }
    }
}
