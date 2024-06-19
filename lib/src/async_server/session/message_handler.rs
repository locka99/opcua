use std::{sync::Arc, time::Instant};

use chrono::Utc;
use parking_lot::RwLock;
use tokio::task::JoinHandle;

use crate::{
    async_server::{
        authenticator::UserToken,
        info::ServerInfo,
        node_manager::{NodeManagers, RequestContext},
        session::services,
        subscriptions::{PendingPublish, SubscriptionCache},
    },
    server::prelude::{
        PublishRequest, ResponseHeader, ServiceFault, SetTriggeringRequest, SetTriggeringResponse,
        StatusCode, SupportedMessage,
    },
};

use super::{controller::Response, instance::Session};

pub(crate) struct MessageHandler {
    node_managers: NodeManagers,
    info: Arc<ServerInfo>,
    subscriptions: Arc<SubscriptionCache>,
}

pub(crate) enum HandleMessageResult {
    AsyncMessage(JoinHandle<Response>),
    PublishResponse(PendingPublishRequest),
    SyncMessage(Response),
}

pub(crate) struct PendingPublishRequest {
    request_id: u32,
    request_handle: u32,
    recv: tokio::sync::oneshot::Receiver<SupportedMessage>,
}

impl PendingPublishRequest {
    pub async fn recv(self) -> Result<Response, String> {
        match self.recv.await {
            Ok(msg) => Ok(Response {
                message: msg,
                request_id: self.request_id,
            }),
            Err(_) => {
                // This shouldn't be possible at all.
                warn!("Failed to receive response to publish request, sender dropped.");
                Ok(Response {
                    message: ServiceFault::new(self.request_handle, StatusCode::BadInternalError)
                        .into(),
                    request_id: self.request_id,
                })
            }
        }
    }
}

pub(super) struct Request<T> {
    pub request: Box<T>,
    pub request_id: u32,
    pub request_handle: u32,
    pub info: Arc<ServerInfo>,
    pub session: Arc<RwLock<Session>>,
    pub token: UserToken,
    pub subscriptions: Arc<SubscriptionCache>,
    pub session_id: u32,
}

macro_rules! service_fault {
    ($req:ident, $status:expr) => {
        Response {
            message: $crate::server::prelude::ServiceFault::new($req.request_handle, $status)
                .into(),
            request_id: $req.request_id,
        }
    };
}

impl<T> Request<T> {
    pub fn new(
        request: Box<T>,
        info: Arc<ServerInfo>,
        request_id: u32,
        request_handle: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
        subscriptions: Arc<SubscriptionCache>,
        session_id: u32,
    ) -> Self {
        Self {
            request,
            request_id,
            request_handle,
            info,
            session,
            token,
            subscriptions,
            session_id,
        }
    }

    pub fn service_fault(&self, status_code: StatusCode) -> Response {
        Response {
            message: ServiceFault::new(self.request_handle, status_code).into(),
            request_id: self.request_id,
        }
    }

    pub fn context(&self) -> RequestContext {
        RequestContext {
            session: self.session.clone(),
            authenticator: self.info.authenticator.clone(),
            token: self.token.clone(),
            current_node_manager_index: 0,
            type_tree: self.info.type_tree.clone(),
            subscriptions: self.subscriptions.clone(),
            session_id: self.session_id,
            info: self.info.clone(),
        }
    }
}

macro_rules! async_service_call {
    ($m:path, $slf:ident, $req:ident, $r:ident) => {
        HandleMessageResult::AsyncMessage(tokio::task::spawn($m(
            $slf.node_managers.clone(),
            Request::new(
                $req,
                $slf.info.clone(),
                $r.request_id,
                $r.request_handle,
                $r.session,
                $r.token,
                $slf.subscriptions.clone(),
                $r.session_id,
            ),
        )))
    };
}

struct RequestData {
    request_id: u32,
    request_handle: u32,
    session: Arc<RwLock<Session>>,
    token: UserToken,
    session_id: u32,
}

impl MessageHandler {
    pub fn new(
        info: Arc<ServerInfo>,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Self {
        Self {
            node_managers,
            info,
            subscriptions,
        }
    }

    pub fn handle_message(
        &mut self,
        message: SupportedMessage,
        session_id: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
        request_id: u32,
    ) -> HandleMessageResult {
        let data = RequestData {
            request_id,
            request_handle: message.request_handle(),
            session,
            token,
            session_id,
        };
        // Session management requests are not handled here.
        match message {
            SupportedMessage::ReadRequest(request) => {
                async_service_call!(services::read, self, request, data)
            }

            SupportedMessage::BrowseRequest(request) => {
                async_service_call!(services::browse, self, request, data)
            }

            SupportedMessage::BrowseNextRequest(request) => {
                async_service_call!(services::browse_next, self, request, data)
            }

            SupportedMessage::TranslateBrowsePathsToNodeIdsRequest(request) => {
                async_service_call!(services::translate_browse_paths, self, request, data)
            }

            SupportedMessage::RegisterNodesRequest(request) => {
                async_service_call!(services::register_nodes, self, request, data)
            }

            SupportedMessage::UnregisterNodesRequest(request) => {
                async_service_call!(services::unregister_nodes, self, request, data)
            }

            SupportedMessage::CreateMonitoredItemsRequest(request) => {
                async_service_call!(services::create_monitored_items, self, request, data)
            }

            SupportedMessage::ModifyMonitoredItemsRequest(request) => {
                async_service_call!(services::modify_monitored_items, self, request, data)
            }

            SupportedMessage::SetMonitoringModeRequest(request) => {
                async_service_call!(services::set_monitoring_mode, self, request, data)
            }

            SupportedMessage::DeleteMonitoredItemsRequest(request) => {
                async_service_call!(services::delete_monitored_items, self, request, data)
            }

            SupportedMessage::SetTriggeringRequest(request) => self.set_triggering(request, data),

            SupportedMessage::PublishRequest(request) => self.publish(request, data),

            SupportedMessage::RepublishRequest(request) => {
                HandleMessageResult::SyncMessage(Response::from_result(
                    self.subscriptions.republish(data.session_id, &request),
                    data.request_handle,
                    data.request_id,
                ))
            }

            SupportedMessage::CreateSubscriptionRequest(request) => {
                HandleMessageResult::SyncMessage(Response::from_result(
                    self.subscriptions.create_subscription(
                        data.session_id,
                        &data.session,
                        &request,
                        &self.info,
                    ),
                    data.request_handle,
                    data.request_id,
                ))
            }

            SupportedMessage::ModifySubscriptionRequest(request) => {
                HandleMessageResult::SyncMessage(Response::from_result(
                    self.subscriptions
                        .modify_subscription(data.session_id, &request, &self.info),
                    data.request_handle,
                    data.request_id,
                ))
            }

            SupportedMessage::SetPublishingModeRequest(request) => {
                HandleMessageResult::SyncMessage(Response::from_result(
                    self.subscriptions
                        .set_publishing_mode(data.session_id, &request),
                    data.request_handle,
                    data.request_id,
                ))
            }

            SupportedMessage::TransferSubscriptionsRequest(request) => {
                HandleMessageResult::SyncMessage(Response {
                    message: self
                        .subscriptions
                        .transfer(&request, data.session_id, &data.session)
                        .into(),
                    request_id: data.request_id,
                })
            }

            SupportedMessage::DeleteSubscriptionsRequest(request) => {
                async_service_call!(services::delete_subscriptions, self, request, data)
            }

            SupportedMessage::HistoryReadRequest(request) => {
                async_service_call!(services::history_read, self, request, data)
            }

            SupportedMessage::HistoryUpdateRequest(request) => {
                async_service_call!(services::history_update, self, request, data)
            }

            SupportedMessage::WriteRequest(request) => {
                async_service_call!(services::write, self, request, data)
            }

            SupportedMessage::QueryFirstRequest(request) => {
                async_service_call!(services::query_first, self, request, data)
            }

            SupportedMessage::QueryNextRequest(request) => {
                async_service_call!(services::query_next, self, request, data)
            }

            SupportedMessage::CallRequest(request) => {
                async_service_call!(services::call, self, request, data)
            }

            SupportedMessage::AddNodesRequest(request) => {
                async_service_call!(services::add_nodes, self, request, data)
            }

            SupportedMessage::AddReferencesRequest(request) => {
                async_service_call!(services::add_references, self, request, data)
            }

            SupportedMessage::DeleteNodesRequest(request) => {
                async_service_call!(services::delete_nodes, self, request, data)
            }

            SupportedMessage::DeleteReferencesRequest(request) => {
                async_service_call!(services::delete_references, self, request, data)
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

    pub async fn delete_session_subscriptions(
        &mut self,
        session_id: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
    ) {
        let ids = self.subscriptions.get_session_subscription_ids(session_id);
        if ids.is_empty() {
            return;
        }

        let context = RequestContext {
            session,
            session_id,
            authenticator: self.info.authenticator.clone(),
            token,
            current_node_manager_index: 0,
            type_tree: self.info.type_tree.clone(),
            subscriptions: self.subscriptions.clone(),
            info: self.info.clone(),
        };

        // Ignore the result
        if let Err(e) = services::delete_subscriptions_inner(
            self.node_managers.clone(),
            ids,
            &self.subscriptions,
            &context,
        )
        .await
        {
            warn!("Cleaning up session subscriptions failed: {e}");
        }
    }

    fn set_triggering(
        &self,
        request: Box<SetTriggeringRequest>,
        data: RequestData,
    ) -> HandleMessageResult {
        let result = self
            .subscriptions
            .set_triggering(
                data.session_id,
                request.subscription_id,
                request.triggering_item_id,
                request.links_to_add.unwrap_or_default(),
                request.links_to_remove.unwrap_or_default(),
            )
            .map(|(add_res, remove_res)| SetTriggeringResponse {
                response_header: ResponseHeader::new_good(&request.request_header),
                add_results: Some(add_res),
                add_diagnostic_infos: None,
                remove_results: Some(remove_res),
                remove_diagnostic_infos: None,
            });

        HandleMessageResult::SyncMessage(Response::from_result(
            result,
            data.request_handle,
            data.request_id,
        ))
    }

    fn publish(&self, request: Box<PublishRequest>, data: RequestData) -> HandleMessageResult {
        let now = Utc::now();
        let now_instant = Instant::now();
        let (send, recv) = tokio::sync::oneshot::channel();
        let timeout = request.request_header.timeout_hint;
        let timeout = if timeout == 0 {
            self.info.config.publish_timeout_default_ms
        } else {
            timeout.into()
        };

        let req = PendingPublish {
            response: send,
            request,
            ack_results: None,
            deadline: now_instant + std::time::Duration::from_millis(timeout),
        };
        match self
            .subscriptions
            .enqueue_publish_request(data.session_id, &now, now_instant, req)
        {
            Ok(_) => HandleMessageResult::PublishResponse(PendingPublishRequest {
                request_id: data.request_id,
                request_handle: data.request_handle,
                recv,
            }),
            Err(e) => HandleMessageResult::SyncMessage(Response {
                message: ServiceFault::new(data.request_handle, e).into(),
                request_id: data.request_id,
            }),
        }
    }
}
