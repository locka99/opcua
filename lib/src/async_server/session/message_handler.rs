use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::{
    async_server::node_manager::NodeManagerWrapper,
    server::prelude::{ServiceFault, StatusCode, SupportedMessage},
};

use super::{controller::Response, instance::Session};

pub(crate) struct MessageHandler {
    node_managers: Arc<Vec<Box<dyn NodeManagerWrapper>>>,
}

pub enum HandleMessageResult {
    AsyncMessage(JoinHandle<Response>),
    SyncMessage(Response),
}

impl MessageHandler {
    pub fn handle_message(
        &mut self,
        message: SupportedMessage,
        session: &mut Session,
        request_id: u32,
    ) -> HandleMessageResult {
        // Session management requests are not handled here.
        match message {
            SupportedMessage::GetEndpointsRequest(request) => {
                todo!();
            }
            SupportedMessage::RegisterServerRequest(request) => {
                todo!();
            }
            SupportedMessage::RegisterServer2Request(request) => {
                todo!();
            }
            SupportedMessage::FindServersRequest(request) => {
                todo!();
            }
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
                })
            }
        }
    }
}
