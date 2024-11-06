use std::sync::Arc;

use crate::{
    client::transport::{SecureChannelEventLoop, TransportPollResult},
    types::{NodeId, StatusCode},
};

use super::Session;

/// This struct manages the task of connecting to the server.
/// It will only make a single attempt, so whatever is calling it is responsible for retries.
pub(super) struct SessionConnector {
    inner: Arc<Session>,
}

/// When the session connects to the server, this describes
/// how that happened, whether a new session was created, or an old session was reactivated.
#[derive(Debug, Clone)]
pub enum SessionConnectMode {
    /// A new session was created with session ID given by the inner [`NodeId`]
    NewSession(NodeId),
    /// An old session was reactivated with session ID given by the inner [`NodeId`]
    ReactivatedSession(NodeId),
}

impl SessionConnector {
    pub fn new(session: Arc<Session>) -> Self {
        Self { inner: session }
    }

    pub async fn try_connect(
        &self,
    ) -> Result<(SecureChannelEventLoop, SessionConnectMode), StatusCode> {
        self.connect_and_activate().await
    }

    async fn connect_and_activate(
        &self,
    ) -> Result<(SecureChannelEventLoop, SessionConnectMode), StatusCode> {
        let mut event_loop = self.inner.channel.connect_no_retry().await?;

        let activate_fut = self.ensure_and_activate_session();
        tokio::pin!(activate_fut);

        let res = loop {
            tokio::select! {
                r = event_loop.poll() => {
                    if let TransportPollResult::Closed(c) = r {
                        return Err(c);
                    }
                },
                r = &mut activate_fut => break r,
            }
        };

        let id = match res {
            Ok(id) => id,
            Err(e) => {
                self.inner.channel.close_channel().await;

                loop {
                    if matches!(event_loop.poll().await, TransportPollResult::Closed(_)) {
                        break;
                    }
                }

                return Err(e);
            }
        };

        Ok((event_loop, id))
    }

    async fn ensure_and_activate_session(&self) -> Result<SessionConnectMode, StatusCode> {
        let should_create_session = self.inner.session_id.load().is_null();

        if should_create_session {
            self.inner.create_session().await?;
        }

        let reconnect = match self.inner.activate_session().await {
            Err(status_code) if !should_create_session => {
                info!(
                    "Session activation failed on reconnect, error = {}, creating a new session",
                    status_code
                );
                self.inner.reset();
                let id = self.inner.create_session().await?;
                self.inner.activate_session().await?;
                SessionConnectMode::NewSession(id)
            }
            Err(e) => return Err(e),
            Ok(_) => {
                let session_id = (**self.inner.session_id.load()).clone();
                if should_create_session {
                    SessionConnectMode::NewSession(session_id)
                } else {
                    SessionConnectMode::ReactivatedSession(session_id)
                }
            }
        };

        self.inner.transfer_subscriptions_from_old_session().await;

        Ok(reconnect)
    }
}
