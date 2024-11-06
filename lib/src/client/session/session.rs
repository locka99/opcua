use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use arc_swap::ArcSwap;
use tokio::{
    sync::watch,
    time::{Duration, Instant},
};

use crate::{
    client::{
        retry::SessionRetryPolicy, transport::tcp::TransportConfiguration, AsyncSecureChannel,
        ClientConfig,
    },
    core::{handle::AtomicHandle, supported_message::SupportedMessage},
    crypto::CertificateStore,
    sync::{Mutex, RwLock},
    types::{ApplicationDescription, DecodingOptions, NodeId, RequestHeader, StatusCode, UAString},
};

use super::{services::subscriptions::state::SubscriptionState, SessionEventLoop, SessionInfo};

#[derive(Clone, Copy)]
pub enum SessionState {
    Disconnected,
    Connected,
    Connecting,
}

lazy_static! {
    static ref NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);
}

/// An OPC-UA session. This session provides methods for all supported services that require an open session.
///
/// Note that not all servers may support all service requests and calling an unsupported API
/// may cause the connection to be dropped. Your client is expected to know the capabilities of
/// the server it is calling to avoid this.
///
pub struct Session {
    pub(super) channel: AsyncSecureChannel,
    pub(super) state_watch_rx: watch::Receiver<SessionState>,
    pub(super) state_watch_tx: watch::Sender<SessionState>,
    pub(super) certificate_store: Arc<RwLock<CertificateStore>>,
    pub(super) session_id: Arc<ArcSwap<NodeId>>,
    pub(super) auth_token: Arc<ArcSwap<NodeId>>,
    pub(super) internal_session_id: AtomicU32,
    pub(super) session_info: SessionInfo,
    pub(super) session_name: UAString,
    pub(super) application_description: ApplicationDescription,
    pub(super) request_timeout: Duration,
    pub(super) publish_timeout: Duration,
    pub(super) recreate_monitored_items_chunk: usize,
    pub(super) session_timeout: f64,
    pub(super) max_inflight_publish: usize,
    pub subscription_state: Mutex<SubscriptionState>,
    pub(super) monitored_item_handle: AtomicHandle,
    pub(super) trigger_publish_tx: watch::Sender<Instant>,
}

impl Session {
    pub(crate) fn new(
        certificate_store: Arc<RwLock<CertificateStore>>,
        session_info: SessionInfo,
        session_name: UAString,
        application_description: ApplicationDescription,
        session_retry_policy: SessionRetryPolicy,
        decoding_options: DecodingOptions,
        config: &ClientConfig,
    ) -> (Arc<Self>, SessionEventLoop) {
        let auth_token: Arc<ArcSwap<NodeId>> = Default::default();
        let (state_watch_tx, state_watch_rx) = watch::channel(SessionState::Disconnected);
        let (trigger_publish_tx, trigger_publish_rx) = watch::channel(Instant::now());

        let session = Arc::new(Session {
            channel: AsyncSecureChannel::new(
                certificate_store.clone(),
                session_info.clone(),
                session_retry_policy.clone(),
                decoding_options,
                config.performance.ignore_clock_skew,
                auth_token.clone(),
                TransportConfiguration {
                    max_pending_incoming: 5,
                    max_inflight: config.performance.max_inflight_messages,
                    send_buffer_size: config.decoding_options.max_chunk_size,
                    recv_buffer_size: config.decoding_options.max_incoming_chunk_size,
                    max_message_size: config.decoding_options.max_message_size,
                    max_chunk_count: config.decoding_options.max_chunk_count,
                },
            ),
            internal_session_id: AtomicU32::new(NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)),
            state_watch_rx,
            state_watch_tx,
            session_id: Default::default(),
            session_info,
            auth_token,
            session_name,
            application_description,
            certificate_store,
            request_timeout: config.request_timeout,
            session_timeout: config.session_timeout as f64,
            publish_timeout: config.publish_timeout,
            max_inflight_publish: config.max_inflight_publish,
            recreate_monitored_items_chunk: config.performance.recreate_monitored_items_chunk,
            subscription_state: Mutex::new(SubscriptionState::new(config.min_publish_interval)),
            monitored_item_handle: AtomicHandle::new(1000),
            trigger_publish_tx,
        });

        (
            session.clone(),
            SessionEventLoop::new(
                session,
                session_retry_policy,
                config.keep_alive_interval,
                trigger_publish_rx,
            ),
        )
    }

    /// Send a message and wait for response, using the default configured timeout.
    ///
    /// In order to set a different timeout, call `send` on the inner channel instead.
    pub(super) async fn send(
        &self,
        request: impl Into<SupportedMessage>,
    ) -> Result<SupportedMessage, StatusCode> {
        self.channel.send(request, self.request_timeout).await
    }

    /// Create a request header with the default timeout.
    pub(super) fn make_request_header(&self) -> RequestHeader {
        self.channel.make_request_header(self.request_timeout)
    }

    /// Reset the session after a hard disconnect, clearing the session ID and incrementing the internal
    /// session counter.
    pub(crate) fn reset(&self) {
        self.session_id.store(Arc::new(NodeId::null()));
        self.internal_session_id.store(
            NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }

    /// Wait for the session to be in either a connected or disconnected state.
    async fn wait_for_state(&self, connected: bool) -> bool {
        let mut rx = self.state_watch_rx.clone();

        let result = rx
            .wait_for(|s| {
                connected && matches!(*s, SessionState::Connected)
                    || !connected && matches!(*s, SessionState::Disconnected)
            })
            .await
            .is_ok();

        #[expect(clippy::let_and_return)]
        result
    }

    /// The internal ID of the session, used to keep track of multiple sessions in the same program.
    pub fn session_id(&self) -> u32 {
        self.internal_session_id.load(Ordering::Relaxed)
    }

    /// Convenience method to wait for a connection to the server.
    ///
    /// You should also monitor the session event loop. If it ends, this method will never return.
    pub async fn wait_for_connection(&self) -> bool {
        self.wait_for_state(true).await
    }

    /// Disconnect from the server and wait until disconnected.
    pub async fn disconnect(&self) -> Result<(), StatusCode> {
        self.close_session().await?;
        self.channel.close_channel().await;

        self.wait_for_state(false).await;

        Ok(())
    }
}
