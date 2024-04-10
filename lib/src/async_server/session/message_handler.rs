use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::{
    async_server::{info::ServerInfo, node_manager::NodeManagerWrapper},
    core::config::Config,
    server::prelude::{
        FindServersResponse, GetEndpointsResponse, ResponseHeader, ServiceFault, StatusCode,
        SupportedMessage,
    },
};

use super::{controller::Response, instance::Session};

pub(crate) struct MessageHandler {
    node_managers: Arc<Vec<Box<dyn NodeManagerWrapper + Send + Sync + 'static>>>,
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
            SupportedMessage::GetEndpointsRequest(request) => {
                // TODO some of the arguments in the request are ignored
                //  localeIds - list of locales to use for human readable strings (in the endpoint descriptions)

                // TODO audit - generate event for failed service invocation

                let endpoints = self
                    .info
                    .endpoints(&request.endpoint_url, &request.profile_uris);
                HandleMessageResult::SyncMessage(Response {
                    message: GetEndpointsResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        endpoints,
                    }
                    .into(),
                    request_id,
                    request_handle,
                })
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

                HandleMessageResult::SyncMessage(Response {
                    message: FindServersResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        servers,
                    }
                    .into(),
                    request_id,
                    request_handle,
                })
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
                    request_handle,
                })
            }
        }
    }
}
