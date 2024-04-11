use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::{
    async_server::{info::ServerInfo, node_manager::NodeManager},
    core::config::Config,
    server::prelude::{
        FindServersResponse, GetEndpointsResponse, ResponseHeader, ServiceFault, StatusCode,
        SupportedMessage,
    },
};

use super::{controller::Response, instance::Session};

pub(crate) struct MessageHandler {
    node_managers: Arc<Vec<Box<dyn NodeManager + Send + Sync + 'static>>>,
    info: Arc<ServerInfo>,
}

pub(crate) enum HandleMessageResult {
    AsyncMessage(JoinHandle<Response>),
    SyncMessage(Response),
}

impl MessageHandler {
    pub fn new(info: Arc<ServerInfo>) -> Self {
        Self {
            node_managers: Default::default(),
            info,
        }
    }

    pub fn handle_message(
        &mut self,
        message: SupportedMessage,
        session: &Session,
        request_id: u32,
    ) -> HandleMessageResult {
        let request_handle = message.request_handle();
        // Session management requests are not handled here.
        match message {
            message => {
                debug!(
                    "Message handler does not handle this kind of message {:?}",
                    message
                );
                HandleMessageResult::SyncMessage(Response {
                    message: ServiceFault::new(
                        message.request_header(),
                        StatusCode::BadServiceUnsupported,
                    )
                    .into(),
                    request_id,
                    request_handle,
                })
            }
        }
    }
}
