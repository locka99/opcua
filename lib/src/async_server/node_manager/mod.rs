use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::server::prelude::{NodeId, ServiceFault, StatusCode, SupportedMessage};

/// Trait for a type that implements logic for responding to requests.
/// Implementations of this trait may make external calls for node information,
/// or do other complex tasks.
///
/// Note that each request is passed to every node manager concurrently.
/// It is up to each node manager to avoid responding to requests for nodes
/// managed by a different node manager.
///
/// Requests are spawned on the tokio thread pool. Avoid making blocking calls in
/// methods on this trait. If you need to do blocking work use `tokio::spawn_blocking`,
/// though you should use async IO as much as possible.
///
/// For a simpler interface see InMemoryNodeManager, use this trait directly
/// if you need to control how all node information is stored.
pub trait NodeManager {
    type TContext: Clone + Send + Sync + 'static;
}

pub(crate) trait NodeManagerWrapper {
    /// Handle a request that go to node managers.
    /// Not all requests go here, session management, subscriptions, and publish are handled
    /// elsewhere.
    fn handle_request(
        &self,
        request: SupportedMessage,
        session_id: NodeId,
    ) -> JoinHandle<SupportedMessage>;
}

pub struct NodeManagerHandle<TNodeManager: NodeManager> {
    manager: Arc<TNodeManager>,
    context: TNodeManager::TContext,
}

impl<TNodeManager: NodeManager + Send + Sync + 'static> NodeManagerWrapper
    for NodeManagerHandle<TNodeManager>
{
    fn handle_request(
        &self,
        request: SupportedMessage,
        session_id: NodeId,
    ) -> JoinHandle<SupportedMessage> {
        todo!()
    }
}

impl<TNodeManager: NodeManager + Send + Sync + 'static> NodeManagerHandle<TNodeManager> {
    pub fn new(
        manager: Arc<TNodeManager>,
        context: TNodeManager::TContext,
    ) -> Box<dyn NodeManagerWrapper> {
        Box::new(Self { manager, context })
    }

    async fn handle_request_inner(
        manager: Arc<TNodeManager>,
        context: TNodeManager::TContext,
        request: SupportedMessage,
    ) -> SupportedMessage {
        match request {
            _ => ServiceFault::new(request.request_header(), StatusCode::BadServiceUnsupported)
                .into(),
        }
    }
}
