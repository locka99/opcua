use std::sync::Arc;

use crate::{
    server::{
        authenticator::{AuthManager, UserToken},
        info::ServerInfo,
        session::instance::Session,
        SubscriptionCache,
    },
    sync::RwLock,
    types::{BrowseDescriptionResultMask, NodeId},
};

use super::{
    view::{ExternalReferenceRequest, NodeMetadata},
    NodeManagers, TypeTree,
};

#[derive(Clone)]
/// Context object passed during writes, contains useful context the node
/// managers can use to execute service calls.
pub struct RequestContext {
    /// The full session object for the session responsible for this service call.
    pub session: Arc<RwLock<Session>>,
    /// The session ID for the session responsible for this service call.
    pub session_id: u32,
    /// The global `AuthManager` object.
    pub authenticator: Arc<dyn AuthManager>,
    /// The current user token.
    pub token: UserToken,
    /// Index of the current node manager.
    pub current_node_manager_index: usize,
    /// Global type tree object.
    pub type_tree: Arc<RwLock<TypeTree>>,
    /// Subscription cache, containing all subscriptions on the server.
    pub subscriptions: Arc<SubscriptionCache>,
    /// Server info object, containing configuration and other shared server
    /// state.
    pub info: Arc<ServerInfo>,
}

/// Resolve a list of references.
pub(crate) async fn resolve_external_references(
    context: &RequestContext,
    node_managers: &NodeManagers,
    references: &[(&NodeId, BrowseDescriptionResultMask)],
) -> Vec<Option<NodeMetadata>> {
    let mut res: Vec<_> = references
        .into_iter()
        .map(|(n, mask)| ExternalReferenceRequest::new(n, *mask))
        .collect();

    for nm in node_managers.iter() {
        let mut items: Vec<_> = res
            .iter_mut()
            .filter(|r| nm.owns_node(r.node_id()))
            .collect();

        nm.resolve_external_references(context, &mut items).await;
    }

    res.into_iter().map(|r| r.into_inner()).collect()
}
